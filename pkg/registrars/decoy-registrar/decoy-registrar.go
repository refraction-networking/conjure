package decoy

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/refraction-networking/conjure/pkg/registrars/lib"
	pb "github.com/refraction-networking/conjure/proto"
	"github.com/refraction-networking/gotapdance/tapdance"

	// td imports assets/
	td "github.com/refraction-networking/gotapdance/tapdance"
	tls "github.com/refraction-networking/utls"
	"github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"
)

/**
 * TODO: enable logging
 */

// timeout for sending TD request and getting a response
const deadlineConnectTDStationMin = 11175
const deadlineConnectTDStationMax = 14231

// deadline to establish TCP connection to decoy
const deadlineTCPtoDecoyMin = deadlineConnectTDStationMin
const deadlineTCPtoDecoyMax = deadlineConnectTDStationMax

type DialFunc = func(ctx context.Context, network, addr string) (net.Conn, error)

type DecoyRegistrar struct {

	// dialContex is a custom dialer to use when establishing TCP connections
	// to decoys. When nil, Dialer.dialContex will be used.
	dialContex DialFunc

	logger logrus.FieldLogger

	// Fields taken from ConjureReg struct
	m             sync.Mutex
	stats         *pb.SessionStats
	sessionIDStr  string
	covertAddress string
}

// CurrentClientLibraryVersion returns the current client library version used
// for feature compatibility support between client and server. Currently I
// don't intend to connect this to the library tag version in any way.
//
// When adding new client versions comment out older versions and add new
// version below with a description of the reason for the new version.
func currentClientLibraryVersion() uint32 {
	// Support for randomizing destination port for phantom connection
	// https://github.com/refraction-networking/gotapdance/pull/108
	return 3

	// // Selection algorithm update - Oct 27, 2022 -- Phantom selection version rework again to use
	// // hkdf for actual uniform distribution across phantom subnets.
	// // https://github.com/refraction-networking/conjure/pull/145
	// return 2

	// // Initial inclusion of client version - added due to update in phantom
	// // selection algorithm that is not backwards compatible to older clients.
	// return 1

	// // No client version indicates any client before this change.
	// return 0
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

func (r *DecoyRegistrar) getPbTransport() pb.TransportType {
	return r.Transport.ID()
}

func (r *DecoyRegistrar) setTCPToDecoy(tcprtt *uint32) {
	r.m.Lock()
	defer r.m.Unlock()

	if r.stats == nil {
		r.stats = &pb.SessionStats{}
	}
	r.stats.TcpToDecoy = tcprtt
}

func (reg *DecoyRegistrar) setTLSToDecoy(tlsrtt *uint32) {
	reg.m.Lock()
	defer reg.m.Unlock()

	if reg.stats == nil {
		reg.stats = &pb.SessionStats{}
	}
	reg.stats.TlsToDecoy = tlsrtt
}

func (r *DecoyRegistrar) generateClientToStation() (*pb.ClientToStation, error) {
	var covert *string
	if len(r.covertAddress) > 0 {
		//[TODO]{priority:medium} this isn't the correct place to deal with signaling to the station
		//transition = pb.C2S_Transition_C2S_SESSION_COVERT_INIT
		covert = &r.covertAddress
	}

	//[reference] Generate ClientToStation protobuf
	// transition := pb.C2S_Transition_C2S_SESSION_INIT
	currentGen := td.Assets().GetGeneration()
	currentLibVer := currentClientLibraryVersion()
	transport := reg.getPbTransport()
	transportParams, err := reg.getPbTransportParams()
	if err != nil {
		// Logger().Debugf("%s failed to marshal transport parameters ", reg.sessionIDStr)
	}

	// remove type url to save space for DNS registration
	// for server side changes see https://github.com/refraction-networking/conjure/pull/163
	transportParams.TypeUrl = ""

	initProto := &pb.ClientToStation{
		ClientLibVersion:    &currentLibVer,
		CovertAddress:       covert,
		DecoyListGeneration: &currentGen,
		V6Support:           reg.getV6Support(),
		V4Support:           reg.getV4Support(),
		Transport:           &transport,
		Flags:               reg.generateFlags(),
		TransportParams:     transportParams,

		DisableRegistrarOverrides: &reg.ConjureSession.DisableRegistrarOverrides,

		//[TODO]{priority:medium} specify width in C2S because different width might
		// 		be useful in different regions (constant for now.)
	}

	if len(reg.phantomSNI) > 0 {
		initProto.MaskedDecoyServerName = &reg.phantomSNI
	}

	for (proto.Size(initProto)+AES_GCM_TAG_SIZE)%3 != 0 {
		initProto.Padding = append(initProto.Padding, byte(0))
	}

	return initProto, nil
}

func NewDecoyRegistrar() *DecoyRegistrar {
	return &DecoyRegistrar{
		logger: tapdance.Logger(),
	}
}

func NewDecoyRegistrarWithDialer(dialer DialFunc) *DecoyRegistrar {
	return &DecoyRegistrar{
		dialContex: dialer,
		logger:     tapdance.Logger(),
	}
}

func (r DecoyRegistrar) createTLSConn(dialConn net.Conn, address string, hostname string, deadline time.Time) (*tls.UConn, error) {
	var err error
	//[reference] TLS to Decoy
	config := tls.Config{ServerName: hostname}
	if config.ServerName == "" {
		// if SNI is unset -- try IP
		config.ServerName, _, err = net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
		// Logger().Debugf("%v SNI was nil. Setting it to %v ", r.sessionIDStr, config.ServerName)
	}
	//[TODO]{priority:medium} parroting Chrome 62 ClientHello -- parrot newer.
	tlsConn := tls.UClient(dialConn, &config, tls.HelloChrome_62)

	err = tlsConn.BuildHandshakeState()
	if err != nil {
		return nil, err
	}
	err = tlsConn.MarshalClientHello()
	if err != nil {
		return nil, err
	}

	tlsConn.SetDeadline(deadline)
	err = tlsConn.Handshake()
	if err != nil {
		return nil, err
	}

	return tlsConn, nil
}

func generateVSP() ([]byte, error) {
	c2s, err := reg.generateClientToStation()
	if err != nil {
		return nil, err
	}

	//[reference] Marshal ClientToStation protobuf
	return proto.Marshal(c2s)
}

func (r *DecoyRegistrar) createRequest(tlsConn *tls.UConn, decoy *pb.TLSDecoySpec) ([]byte, error) {
	//[reference] generate and encrypt variable size payload
	vsp, err := reg.generateVSP()
	if err != nil {
		return nil, err
	}
	if len(vsp) > int(^uint16(0)) {
		return nil, fmt.Errorf("Variable-Size Payload exceeds %v", ^uint16(0))
	}
	encryptedVsp, err := aesGcmEncrypt(vsp, reg.keys.VspKey, reg.keys.VspIv)
	if err != nil {
		return nil, err
	}

	//[reference] generate and encrypt fixed size payload
	fsp := reg.generateFSP(uint16(len(encryptedVsp)))
	encryptedFsp, err := aesGcmEncrypt(fsp, reg.keys.FspKey, reg.keys.FspIv)
	if err != nil {
		return nil, err
	}

	var tag []byte // tag will be base-64 style encoded
	tag = append(encryptedVsp, reg.keys.Representative...)
	tag = append(tag, encryptedFsp...)

	httpRequest := generateHTTPRequestBeginning(decoy.GetHostname())
	keystreamOffset := len(httpRequest)
	keystreamSize := (len(tag)/3+1)*4 + keystreamOffset // we can't use first 2 bits of every byte
	wholeKeystream, err := tlsConn.GetOutKeystream(keystreamSize)
	if err != nil {
		return nil, err
	}
	keystreamAtTag := wholeKeystream[keystreamOffset:]
	httpRequest = append(httpRequest, reverseEncrypt(tag, keystreamAtTag)...)
	httpRequest = append(httpRequest, []byte("\r\n\r\n")...)
	return httpRequest, nil
}

func (r DecoyRegistrar) Register(cjSession *tapdance.ConjureSession, ctx context.Context) (*tapdance.ConjureReg, error) {
	logger := r.logger.WithFields(logrus.Fields{"type": "unidirectional", "sessionID": cjSession.IDString()})

	logger.Debugf("Registering V4 and V6 via DecoyRegistrar")

	reg, _, err := cjSession.UnidirectionalRegData(pb.RegistrationSource_API.Enum())
	if err != nil {
		logger.Errorf("Failed to prepare registration data: %v", err)
		return nil, lib.ErrRegFailed
	}

	// Choose N (width) decoys from decoylist
	decoys, err := cjSession.Decoys()
	if err != nil {
		logger.Warnf("failed to select decoys: %v", err)
		return nil, err
	}

	if r.dialContex != nil {
		reg.Dialer = r.dialContex
	}

	// //[TODO]{priority:later} How to pass context to multiple registration goroutines?
	if ctx == nil {
		ctx = context.Background()
	}

	width := uint(len(decoys))
	if width < cjSession.Width {
		logger.Warnf("Using width %v (default %v)", width, cjSession.Width)
	}

	//[reference] Send registrations to each decoy
	dialErrors := make(chan error, width)
	for _, decoy := range decoys {
		logger.Debugf("Sending Reg: %v, %v", decoy.GetHostname(), decoy.GetIpAddrStr())
		//decoyAddr := decoy.GetIpAddrStr()
		go r.Send(ctx, reg, decoy, dialErrors)
	}

	//[reference] Dial errors happen immediately so block until all N dials complete
	var unreachableCount uint = 0
	for err := range dialErrors {
		if err != nil {
			logger.Debugf("%v", err)
			if dialErr, ok := err.(tapdance.RegError); ok && dialErr.Code() == tapdance.Unreachable {
				// If we failed because ipv6 network was unreachable try v4 only.
				unreachableCount++
				if unreachableCount < width {
					continue
				} else {
					break
				}
			}
		}
		//[reference] if we succeed or fail for any other reason then the network is reachable and we can continue
		break
	}

	//[reference] if ALL fail to dial return error (retry in parent if ipv6 unreachable)
	if unreachableCount == width {
		logger.Debugf("NETWORK UNREACHABLE")
		return nil, tapdance.NewRegError(tapdance.Unreachable, "All decoys failed to register -- Dial Unreachable")
	}

	// randomized sleeping here to break the intraflow signal
	toSleep := reg.GetRandomDuration(3000, 212, 3449)
	logger.Debugf("Successfully sent registrations, sleeping for: %v", toSleep)
	lib.SleepWithContext(ctx, toSleep)

	return reg, nil
}

func (r *DecoyRegistrar) Send(ctx context.Context, reg *tapdance.ConjureReg, decoy *pb.TLSDecoySpec, dialError chan error) {

	deadline, deadlineAlreadySet := ctx.Deadline()
	if !deadlineAlreadySet {
		deadline = time.Now().Add(getRandomDuration(deadlineTCPtoDecoyMin, deadlineTCPtoDecoyMax))
	}
	childCtx, childCancelFunc := context.WithDeadline(ctx, deadline)
	defer childCancelFunc()

	//[reference] TCP to decoy
	tcpToDecoyStartTs := time.Now()

	//[Note] decoy.GetIpAddrStr() will get only v4 addr if a decoy has both
	dialConn, err := r.dialContex(childCtx, "tcp", decoy.GetIpAddrStr())

	r.setTCPToDecoy(durationToU32ptrMs(time.Since(tcpToDecoyStartTs)))
	if err != nil {
		if opErr, ok := err.(*net.OpError); ok && opErr.Err.Error() == "connect: network is unreachable" {
			dialError <- RegError{msg: err.Error(), code: Unreachable}
			return
		}
		dialError <- err
		return
	}

	//[reference] connection stats tracking
	rtt := rttInt(uint32(time.Since(tcpToDecoyStartTs).Milliseconds()))
	delay := getRandomDuration(1061*rtt*2, 1953*rtt*3) //[TODO]{priority:@sfrolov} why these values??
	TLSDeadline := time.Now().Add(delay)

	tlsToDecoyStartTs := time.Now()
	tlsConn, err := r.createTLSConn(dialConn, decoy.GetIpAddrStr(), decoy.GetHostname(), TLSDeadline)
	if err != nil {
		dialConn.Close()
		msg := fmt.Sprintf("%v - %v createConn: %v", decoy.GetHostname(), decoy.GetIpAddrStr(), err.Error())
		dialError <- RegError{msg: msg, code: TLSError}
		return
	}
	r.setTLSToDecoy(durationToU32ptrMs(time.Since(tlsToDecoyStartTs)))

	//[reference] Create the HTTP request for the registration
	httpRequest, err := reg.createRequest(tlsConn, decoy)
	if err != nil {
		msg := fmt.Sprintf("%v - %v createReq: %v", decoy.GetHostname(), decoy.GetIpAddrStr(), err.Error())
		dialError <- RegError{msg: msg, code: TLSError}
		return
	}

	//[reference] Write reg into conn
	_, err = tlsConn.Write(httpRequest)
	if err != nil {
		// // This will not get printed because it is executed in a goroutine.
		// Logger().Errorf("%v - %v Could not send Conjure registration request, error: %v", decoy.GetHostname(), decoy.GetIpAddrStr(), err.Error())
		tlsConn.Close()
		msg := fmt.Sprintf("%v - %v Write: %v", decoy.GetHostname(), decoy.GetIpAddrStr(), err.Error())
		dialError <- RegError{msg: msg, code: TLSError}
		return
	}

	dialError <- nil
	readAndClose(dialConn, time.Second*15)
}

// Move to other file eventually?
func GetRandomDuration(base, min, max int) time.Duration {
	addon := getRandInt(min, max) / 1000 // why this min and max???
	rtt := rttInt(reg.getTcpToDecoy())
	return time.Millisecond * time.Duration(base+rtt*addon)
}
