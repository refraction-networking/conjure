package client

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	mrand "math/rand"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/refraction-networking/conjure/pkg/client/assets"
	"github.com/refraction-networking/conjure/pkg/core"
	"github.com/refraction-networking/conjure/pkg/core/interfaces"
	"github.com/refraction-networking/conjure/pkg/log"
	ps "github.com/refraction-networking/conjure/pkg/phantoms"
	pb "github.com/refraction-networking/conjure/proto"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

// ErrNoOpenConns indicates that the client Failed to establish a connection with any phantom addr
var ErrNoOpenConns = errors.New("no open connections")

// DialConjure - Perform Registration and Dial on an existing Conjure session
func DialConjure(ctx context.Context, cjSession *ConjureSession, registrationMethod interfaces.Registrar) (net.Conn, error) {

	if cjSession == nil {
		return nil, fmt.Errorf("No Session Provided")
	}

	// Prepare registrar specific keys
	err := registrationMethod.PrepareRegKeys(getStationKey())
	if err != nil {
		return nil, err
	}
	// Choose Phantom Address in Register depending on v6 support.
	reg, err := registrationMethod.Register(ctx, cjSession)
	if err != nil {
		log.Debugf("%v Failed to register: %v", cjSession.IDString(), err)
		return nil, err
	}

	registration, ok := reg.(*ConjureReg)
	if !ok {
		return nil, fmt.Errorf("Unknown registration Returned")
	}

	tp, isConnecting := cjSession.Transport.(interfaces.ConnectingTransport)
	if isConnecting {
		if tp.DisableRegDelay() {
			cjSession.RegDelay = 0
		}
	}

	sleepWithContext(ctx, cjSession.RegDelay)

	log.Debugf("%v Attempting to Connect using %s ...", cjSession.IDString(), registration.Transport.Name())
	return registration.Connect(ctx, cjSession.Dialer)
}

// ConjureReg - Registration structure created for each individual registration within a session.
type ConjureReg struct {
	interfaces.Transport
	*ConjureSession

	phantom4       *net.IP
	phantom6       *net.IP
	phantomDstPort uint16
	useProxyHeader bool
	covertAddress  string
	v6Support      IPSupport

	m sync.Mutex

	// THIS IS REQUIRED TO INTERFACE WITH PSIPHON ANDROID
	//		we use their dialer to prevent connection loopback into our own proxy
	//		connection when tunneling the whole device.
	Dialer func(context.Context, string, string) (net.Conn, error)
}

func (reg *ConjureReg) connect(ctx context.Context, addr string, dialer dialFunc) (net.Conn, error) {
	//[reference] Create Context with deadline
	deadline, deadlineAlreadySet := ctx.Deadline()
	if !deadlineAlreadySet {
		//[reference] randomized timeout to Dial phantom address
		deadline = time.Now().Add(reg.getRandomDuration(0, 1461*2, 2453*3))
	}
	childCtx, childCancelFunc := context.WithDeadline(ctx, deadline)
	defer childCancelFunc()

	//[reference] Connect to Phantom Host
	phantomAddr := net.JoinHostPort(addr, strconv.Itoa(int(reg.phantomDstPort)))

	return dialer(childCtx, "tcp", "", phantomAddr)
}

func (reg *ConjureReg) getFirstConnection(ctx context.Context, dialer dialFunc, phantoms []*net.IP) (net.Conn, error) {
	connChannel := make(chan resultTuple, len(phantoms))
	for _, p := range phantoms {
		if p == nil {
			connChannel <- resultTuple{nil, fmt.Errorf("nil addr")}
			continue
		}
		go func(phantom *net.IP) {
			conn, err := reg.connect(ctx, phantom.String(), dialer)
			if err != nil {
				log.Infof("%v failed to dial phantom %v: %v", reg.IDString(), phantom.String(), err)
				connChannel <- resultTuple{nil, err}
				return
			}
			log.Infof("%v Connected to phantom %v using transport %s", reg.IDString(), net.JoinHostPort(phantom.String(), strconv.Itoa(int(reg.phantomDstPort))), reg.Transport)
			connChannel <- resultTuple{conn, nil}
		}(p)
	}

	open := len(phantoms)
	for open > 0 {
		rt := <-connChannel
		if rt.err != nil {
			open--
			continue
		}

		// If we made it here we're returning the connection, so
		// set up a goroutine to close the others
		go func() {
			// Close all but one connection (the good one)
			for open > 1 {
				t := <-connChannel
				if t.err == nil {
					t.conn.Close()
				}
				open--
			}
		}()

		return rt.conn, nil
	}

	return nil, ErrNoOpenConns
}

// Connect - Use a registration (result of calling Register) to connect to a phantom
// Note: This is hacky but should work for v4, v6, or both as any nil phantom addr will
// return a dial error and be ignored.
func (reg *ConjureReg) Connect(ctx context.Context, dialer dialFunc) (net.Conn, error) {
	phantoms := []*net.IP{reg.phantom4, reg.phantom6}

	// Prepare the transport by generating any necessary keys
	pubKey := getStationKey()
	err := reg.Transport.PrepareKeys(pubKey, reg.Keys.SharedSecret, reg.Keys.Reader)
	if err != nil {
		return nil, err
	}

	switch transport := reg.Transport.(type) {
	case interfaces.WrappingTransport:
		conn, err := reg.getFirstConnection(ctx, dialer, phantoms)
		if err != nil {
			log.Infof("%v failed to form phantom connection: %v", reg.IDString(), err)
			return nil, err
		}

		conn, err = transport.WrapConn(conn)
		if err != nil {
			log.Infof("WrapConn failed")
			return nil, err
		}

		return conn, nil
	case interfaces.ConnectingTransport:
		transportDialer, err := transport.WrapDial(dialer)
		if err != nil {
			return nil, fmt.Errorf("error wrapping transport dialer: %v", err)
		}

		conn, err := reg.getFirstConnection(ctx, transportDialer, phantoms)
		if err != nil {
			return nil, fmt.Errorf("failed to dialing connecting transport: %v", err)
		}

		return conn, nil
	}

	return nil, fmt.Errorf("transport does not implement any transport interface")
}

// UnpackRegResp unpacks the RegistrationResponse message sent back by the station. This unpacks
// any field overrides sent by the registrar. When using a bidirectional registration method
// the server chooses the phantom IP and Port by default. Overrides to transport parameters
// are applied when reg.DisableRegistrarOverrides is false.
func (reg *ConjureReg) UnpackRegResp(regResp *pb.RegistrationResponse) error {
	if regResp == nil {
		return nil
	}

	if (reg.v6Support&V4) == V4 && (reg.v6Support&V6) == V6 {
		// Case where cjSession.V6Support == both
		// Save the ipv4address in the Conjure Reg struct (phantom4) to return
		ip4 := make(net.IP, 4)
		addr4 := regResp.GetIpv4Addr()
		binary.BigEndian.PutUint32(ip4, addr4)
		reg.phantom4 = &ip4

		// Save the ipv6address in the Conjure Reg struct (phantom6) to return
		addr6 := net.IP(regResp.GetIpv6Addr())
		reg.phantom6 = &addr6
	} else if reg.v6Support&V4 == V4 {
		// Save the ipv4address in the Conjure Reg struct (phantom4) to return
		ip4 := make(net.IP, 4)
		addr4 := regResp.GetIpv4Addr()
		binary.BigEndian.PutUint32(ip4, addr4)
		reg.phantom4 = &ip4
	} else if reg.v6Support&V6 == V6 {
		// Save the ipv6address in the Conjure Reg struct (phantom6) to return
		addr6 := net.IP(regResp.GetIpv6Addr())
		reg.phantom6 = &addr6
	} else {
		return fmt.Errorf("unknown v4/v6 support")
	}

	p := uint16(regResp.GetDstPort())
	if p != 0 {
		reg.phantomDstPort = p
	} else if reg.phantomDstPort == 0 {
		// If a bidirectional registrar does not support randomization (or doesn't set the port in the
		// registration response we default to the original port we used for all transports).
		reg.phantomDstPort = 443
	}

	maybeTP := regResp.GetTransportParams()
	if maybeTP != nil && !reg.DisableRegistrarOverrides {
		// If an error occurs while setting transport parameters give up as continuing would likely
		// lead to incongruence between the client and station and an unserviceable connection.
		params, err := reg.Transport.ParseParams(maybeTP)
		if err != nil {
			return fmt.Errorf("Param Parse error: %w", err)
		}
		err = reg.Transport.SetParams(params, true)
		if err != nil {
			return fmt.Errorf("Param Parse error: %w", err)
		}
	} else if maybeTP != nil && reg.DisableRegistrarOverrides {
		return fmt.Errorf("registrar failed to respect disabled overrides")
	}

	// Client config -- check if not nil in the registration response
	if regResp.GetClientConf() != nil {
		currGen := assets.Assets().GetGeneration()
		incomingGen := regResp.GetClientConf().GetGeneration()
		log.Debugf("received clientconf in regResponse w/ gen %d", incomingGen)
		if currGen < incomingGen {
			log.Debugf("Updating clientconf %d -> %d", currGen, incomingGen)
			_err := assets.Assets().SetClientConf(regResp.GetClientConf())
			if _err != nil {
				log.Warnf("could not set ClientConf in bidirectional API: %v", _err.Error())
			}
		}
	}

	return nil
}

func (reg *ConjureReg) getPbTransport() pb.TransportType {
	return reg.Transport.ID()
}

func (reg *ConjureReg) getPbTransportParams() (*anypb.Any, error) {
	var m proto.Message
	m, err := reg.Transport.GetParams()
	if err != nil {
		return nil, err
	} else if m == nil {
		return nil, nil
	}
	return anypb.New(m)
}

func (reg *ConjureReg) generateFlags() *pb.RegistrationFlags {
	flags := &pb.RegistrationFlags{}
	mask := defaultFlags
	if reg.useProxyHeader {
		mask |= flagProxyHeader
	}

	uploadOnly := mask&flagUploadOnly == flagUploadOnly
	proxy := mask&flagProxyHeader == flagProxyHeader
	til := mask&flagUseTIL == flagUseTIL

	flags.UploadOnly = &uploadOnly
	flags.ProxyHeader = &proxy
	flags.Use_TIL = &til

	return flags
}

func (reg *ConjureReg) generateClientToStation(ctx context.Context) (*pb.ClientToStation, error) {
	var covert *string
	if len(reg.covertAddress) > 0 {
		//[TODO]{priority:medium} this isn't the correct place to deal with signaling to the station
		//transition = pb.C2S_Transition_C2S_SESSION_COVERT_INIT
		covert = &reg.covertAddress
	}

	//[reference] Generate ClientToStation protobuf
	// transition := pb.C2S_Transition_C2S_SESSION_INIT
	currentGen := assets.Assets().GetGeneration()
	currentLibVer := core.CurrentClientLibraryVersion()
	transport := reg.getPbTransport()

	err := reg.Transport.Prepare(ctx, reg.ConjureSession.Dialer)
	if err != nil {
		return nil, fmt.Errorf("error preparing transport: %v", err)
	}

	transportParams, err := reg.getPbTransportParams()
	if err != nil {
		log.Debugf("%s failed to marshal transport parameters ", reg.IDString())
	}

	// remove type url to save space for DNS registration
	// for server side changes see https://github.com/refraction-networking/conjure/pull/163
	transportParams.TypeUrl = ""

	initProto := &pb.ClientToStation{
		ClientLibVersion:    &currentLibVer,
		CovertAddress:       covert,
		DecoyListGeneration: &currentGen,
		V6Support:           reg.ConjureSession.GetV6Support(),
		V4Support:           reg.ConjureSession.GetV4Support(),
		Transport:           &transport,
		Flags:               reg.generateFlags(),
		TransportParams:     transportParams,

		DisableRegistrarOverrides: &reg.ConjureSession.DisableRegistrarOverrides,

		//[TODO]{priority:medium} specify width in C2S because different width might
		// 		be useful in different regions (constant for now.)
	}

	for (proto.Size(initProto)+core.AES_GCM_TAG_SIZE)%3 != 0 {
		initProto.Padding = append(initProto.Padding, byte(0))
	}

	return initProto, nil
}

// Phantom4 returns the ipv4 phantom address
func (reg *ConjureReg) Phantom4() net.IP {
	return *reg.phantom4
}

// Phantom6 returns the ipv6 phantom address
func (reg *ConjureReg) Phantom6() net.IP {
	return *reg.phantom6
}

func (reg *ConjureReg) digestStats() string {
	//[TODO]{priority:eventually} add decoy details to digest
	if reg == nil || reg.stats == nil {
		return "{result:\"no stats tracked\"}"
	}

	reg.m.Lock()
	defer reg.m.Unlock()
	return fmt.Sprintf("{result:\"success\", tcp_to_decoy:%v, tls_to_decoy:%v, total_time_to_connect:%v}",
		reg.stats.GetTcpToDecoy(),
		reg.stats.GetTlsToDecoy(),
		reg.stats.GetTotalTimeToConnect())
}

func sleepWithContext(ctx context.Context, duration time.Duration) {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-ctx.Done():
	}
}

// var phantomSubnets = []conjurePhantomSubnet{
// 	{subnet: "192.122.190.0/24", weight: 90.0},
// 	{subnet: "2001:48a8:687f:1::/64", weight: 90.0},
// 	{subnet: "141.219.0.0/16", weight: 10.0},
// 	{subnet: "35.8.0.0/16", weight: 10.0},
// }

// SelectPhantom - select one phantom IP address based on shared secret
func SelectPhantom(seed []byte, support IPSupport) (*net.IP, *net.IP, bool, error) {
	phantomSubnets := assets.Assets().GetPhantomSubnets()

	if (support&V4 == V4) && (support&V6 == V6) {
		phantomIPv4, err := ps.SelectPhantom(seed, phantomSubnets, ps.V4Only, true)
		if err != nil {
			return nil, nil, false, err
		}
		phantomIPv6, err := ps.SelectPhantom(seed, phantomSubnets, ps.V6Only, true)
		if err != nil {
			return nil, nil, false, err
		}
		return phantomIPv4.IP(), phantomIPv6.IP(), phantomIPv4.SupportRandomPort() && phantomIPv6.SupportRandomPort(), nil
	} else if support&V4 == V4 {
		phantomIPv4, err := ps.SelectPhantom(seed, phantomSubnets, ps.V4Only, true)
		if err != nil {
			return nil, nil, false, err
		}
		return phantomIPv4.IP(), nil, phantomIPv4.SupportRandomPort(), nil
	} else if support&V6 == V6 {
		phantomIPv6, err := ps.SelectPhantom(seed, phantomSubnets, ps.V6Only, true)
		if err != nil {
			return nil, nil, false, err
		}
		return nil, phantomIPv6.IP(), phantomIPv6.SupportRandomPort(), nil
	} else {
		return nil, nil, false, fmt.Errorf("unknown v4/v6 support")
	}
}

func getStationKey() [32]byte {
	return *assets.Assets().GetConjurePubkey()
}

// getRandomDuration returns a random duration that
func (reg *ConjureReg) getRandomDuration(base, min, max int) time.Duration {
	addon := getRandInt(min, max) / 1000 // why this min and max???
	rtt := rttInt(reg.getTCPToDecoy())
	return time.Millisecond * time.Duration(base+rtt*addon)
}

// Tries to get crypto random int in range [min, max]
// In case of crypto failure -- return insecure pseudorandom
func getRandInt(min int, max int) int {
	// I can't believe Golang is making me do that
	// Flashback to awful C/C++ libraries
	diff := max - min
	if diff < 0 {
		// r.logger.Warningf("getRandInt(): max is less than min")
		min = max
		diff *= -1
	} else if diff == 0 {
		return min
	}
	var v int64
	err := binary.Read(rand.Reader, binary.LittleEndian, &v)
	if v < 0 {
		v *= -1
	}
	if err != nil {
		log.Warnf("Unable to securely get getRandInt(): " + err.Error())
		v = mrand.Int63()
	}
	return min + int(v%int64(diff+1))
}

func (reg *ConjureReg) getTCPToDecoy() uint32 {
	if reg == nil {
		return 0
	}
	reg.m.Lock()
	defer reg.m.Unlock()
	if reg.stats != nil {
		return reg.stats.GetTcpToDecoy()
	}
	return 0
}

func rttInt(millis uint32) int {
	defaultValue := 300
	if millis == 0 {
		return defaultValue
	}
	return int(millis)
}

// RegError - Registration Error passed during registration to indicate failure mode
type RegError struct {
	code uint
	msg  string
}

func NewRegError(code uint, msg string) RegError {
	return RegError{code: code, msg: msg}
}

func (err RegError) Error() string {
	return fmt.Sprintf("Registration Error [%v]: %v", err.CodeStr(), err.msg)
}

func (err RegError) Code() uint {
	return err.code
}

// CodeStr - Get desctriptor associated with error code
func (err RegError) CodeStr() string {
	switch err.code {
	case Unreachable:
		return "UNREACHABLE"
	case DialFailure:
		return "DIAL_FAILURE"
	case NotImplemented:
		return "NOT_IMPLEMENTED"
	case TLSError:
		return "TLS_ERROR"
	default:
		return "UNKNOWN"
	}
}

// removeLaddr removes the laddr field in dialer
func removeLaddr(dialer func(ctx context.Context, network, laddr, raddr string) (net.Conn, error)) func(ctx context.Context, network, raddr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		return dialer(ctx, network, "", addr)
	}
}

const (
	// Unreachable -Dial Error Unreachable -- likely network unavailable (i.e. ipv6 error)
	Unreachable = iota

	// DialFailure - Dial Error Other than unreachable
	DialFailure

	// NotImplemented - Related Function Not Implemented
	NotImplemented

	// TLSError (Expired, Wrong-Host, Untrusted-Root, ...)
	TLSError

	// Unknown - Error occurred without obvious explanation
	Unknown
)

func init() {
	sessionsTotal.Store(0)
}
