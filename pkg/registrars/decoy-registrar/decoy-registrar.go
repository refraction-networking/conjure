package decoy

import (
	"context"
	"fmt"
	golog "log"
	"math/big"
	"net"
	"os"
	"sync"
	"time"

	"github.com/refraction-networking/conjure/pkg/client"
	"github.com/refraction-networking/conjure/pkg/client/assets"
	"github.com/refraction-networking/conjure/pkg/core"
	"github.com/refraction-networking/conjure/pkg/log"
	"github.com/refraction-networking/conjure/pkg/registrars/lib"
	pb "github.com/refraction-networking/conjure/proto"
	tls "github.com/refraction-networking/utls"
)

// timeout for sending TD request and getting a response
const deadlineConnectTDStationMin = 11175
const deadlineConnectTDStationMax = 14231

// deadline to establish TCP connection to decoy
const deadlineTCPtoDecoyMin = deadlineConnectTDStationMin
const deadlineTCPtoDecoyMax = deadlineConnectTDStationMax

// Fixed-Size-Payload has a 1 byte flags field.
// bit 0 (1 << 7) determines if flow is bidirectional(0) or upload-only(1)
// bit 1 (1 << 6) enables dark-decoys
// bits 2-5 are unassigned
// bit 6 determines whether PROXY-protocol-formatted string will be sent
// bit 7 (1 << 0) signals to use TypeLen outer proto
var (
	tdFlagUploadOnly = uint8(1 << 7)
	// tdFlagDarkDecoy   = uint8(1 << 6)
	tdFlagProxyHeader = uint8(1 << 1)
	tdFlagUseTIL      = uint8(1 << 0)
)

var defaultFlags = tdFlagUseTIL

// DialFunc is a function that establishes network connections to decoys. This Dial does not require
// a local address.
type DialFunc = func(ctx context.Context, network, addr string) (net.Conn, error)

// DecoyRegistrar implements the Registrar interface for the Decoy Registration method.
type DecoyRegistrar struct {

	// dialContex is a custom dialer to use when establishing TCP connections
	// to decoys. When nil, Dialer.dialContex will be used.
	dialContex DialFunc

	logger *log.Logger

	// Fields taken from ConjureReg struct
	m     sync.Mutex
	stats *pb.SessionStats
	// add Width, sharedKeys necessary stuff (2nd line in struct except ConjureSeed)
	// Keys
	fspKey, fspIv, vspKey, vspIv []byte

	Width uint

	ClientHelloID tls.ClientHelloID
}

// NewDecoyRegistrar returns a decoy registrar with the default `net` dialer.
func NewDecoyRegistrar() *DecoyRegistrar {
	d := &net.Dialer{}
	return NewDecoyRegistrarWithDialFn(d.DialContext)
}

// NewDecoyRegistrarWithDialFn returns a decoy registrar with custom dialer.
//
// Deprecated: Set dialer in Dialer.DialWithLaddr instead.
func NewDecoyRegistrarWithDialFn(dialer DialFunc) *DecoyRegistrar {
	return &DecoyRegistrar{
		dialContex:    dialer,
		logger:        log.New(os.Stdout, "reg: Decoy, ", golog.Ldate|golog.Lmicroseconds),
		ClientHelloID: tls.HelloChrome_62,
		Width:         5,
	}
}

func (r *DecoyRegistrar) setTCPToDecoy(tcprtt *uint32) {
	r.m.Lock()
	defer r.m.Unlock()

	if r.stats == nil {
		r.stats = &pb.SessionStats{}
	}
	r.stats.TcpToDecoy = tcprtt
}

func (r *DecoyRegistrar) setTLSToDecoy(tlsrtt *uint32) {
	r.m.Lock()
	defer r.m.Unlock()

	if r.stats == nil {
		r.stats = &pb.SessionStats{}
	}
	r.stats.TlsToDecoy = tlsrtt
}

// PrepareRegKeys prepares key materials specific to the registrar
func (r *DecoyRegistrar) PrepareRegKeys(pubkey [32]byte) error {
	return nil
}

// getRandomDurationByRTT returns a random duration between min and max in milliseconds adding base.
func (r *DecoyRegistrar) getRandomDurationByRTT(base, min, max int) time.Duration {
	addon := getRandInt(min, max) / 1000 // why this min and max???
	rtt := rttInt(r.getTCPToDecoy())
	return time.Millisecond * time.Duration(base+rtt*addon)
}

func (r *DecoyRegistrar) getTCPToDecoy() uint32 {
	if r == nil {
		return 0
	}
	r.m.Lock()
	defer r.m.Unlock()
	if r.stats != nil {
		return r.stats.GetTcpToDecoy()
	}
	return 0
}

func (r *DecoyRegistrar) createTLSConn(dialConn net.Conn, address string, hostname string, deadline time.Time) (*tls.UConn, error) {
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
	tlsConn := tls.UClient(dialConn, &config, r.ClientHelloID)

	err = tlsConn.BuildHandshakeState()
	if err != nil {
		return nil, err
	}
	err = tlsConn.MarshalClientHello()
	if err != nil {
		return nil, err
	}

	err = tlsConn.SetDeadline(deadline)
	if err != nil {
		return nil, err
	}

	err = tlsConn.Handshake()
	if err != nil {
		return nil, err
	}

	return tlsConn, nil
}

func (r *DecoyRegistrar) createRequest(tlsConn *tls.UConn, decoy *pb.TLSDecoySpec, cjSession *client.ConjureSession) ([]byte, error) {
	//[reference] generate and encrypt variable size payload
	vsp, err := generateVSP(cjSession)
	if err != nil {
		return nil, err
	}
	if len(vsp) > int(^uint16(0)) {
		return nil, fmt.Errorf("Variable-Size Payload exceeds %v", ^uint16(0))
	}
	encryptedVsp, err := aesGcmEncrypt(vsp, r.vspKey, r.vspIv)
	if err != nil {
		return nil, err
	}

	//[reference] generate and encrypt fixed size payload
	fsp := generateFSP(uint16(len(encryptedVsp)))
	encryptedFsp, err := aesGcmEncrypt(fsp, r.fspKey, r.fspIv)
	if err != nil {
		return nil, err
	}

	var tag []byte // tag will be base-64 style encoded
	tag = append(encryptedVsp, cjSession.Keys.Representative...)
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

// Register implements the Registrar interface for he DecoyRegistrar type

// Register implements the conjure Registrar interface.
func (r *DecoyRegistrar) Register(ctx context.Context, cjSession *client.ConjureSession) (*client.ConjureReg, error) {
	fields := fmt.Sprintf("type:unidirectional, sessionID:%v", cjSession.IDString())
	r.logger.Debugf("Registering V4 and V6 via DecoyRegistrar [%s]", fields)

	reg, _, err := cjSession.UnidirectionalRegData(ctx, pb.RegistrationSource_API.Enum())
	if err != nil {
		r.logger.Errorf("Failed to prepare registration data [%s]: %v", fields, err)
		return nil, lib.ErrRegFailed
	}

	// Choose N (width) decoys from decoylist
	decoys, err := selectDecoys(cjSession.Keys.SharedSecret, uint(cjSession.V6Support), r.Width)
	if err != nil {
		r.logger.Warnf("failed to select decoys [%s]: %v", fields, err)
		return nil, err
	}

	// //[TODO]{priority:later} How to pass context to multiple registration goroutines?
	if ctx == nil {
		ctx = context.Background()
	}

	width := uint(len(decoys))
	if width < r.Width {
		r.logger.Warnf("Using width %v (default %v)", width, r.Width)
	}

	//[reference] Send registrations to each decoy
	dialErrors := make(chan error, width)
	for _, decoy := range decoys {
		r.logger.Debugf("[%s] Sending Reg: %v, %v", fields, decoy.GetHostname(), decoy.GetIpAddrStr())
		//decoyAddr := decoy.GetIpAddrStr()
		go r.send(ctx, cjSession, decoy, dialErrors)
	}

	//[reference] Dial errors happen immediately so block until all N dials complete
	var unreachableCount uint = 0
	for err := range dialErrors {
		if err != nil {
			r.logger.Debugf("[%s] %v", fields, err)
			if dialErr, ok := err.(client.RegError); ok && dialErr.Code() == client.Unreachable {
				// If we failed because ipv6 network was unreachable try v4 only.
				unreachableCount++
				if unreachableCount < width {
					continue
				} else {
					break
				}
			}
		}
		//[reference] if we succeed or fail for any other reason then the network is reachable and
		//we can continue
		break
	}

	//[reference] if ALL fail to dial return error (retry in parent if ipv6 unreachable)
	if unreachableCount == width {
		r.logger.Debugf("NETWORK UNREACHABLE [%s]", fields)
		return nil, client.NewRegError(client.Unreachable, "All decoys failed to register -- Dial Unreachable")
	}

	// randomized sleeping here to break the intraflow signal
	toSleep := r.getRandomDurationByRTT(3000, 212, 3449)
	r.logger.Debugf("[%s] Successfully sent registrations, sleeping for: %v", fields, toSleep)
	lib.SleepWithContext(ctx, toSleep)

	return reg, nil
}

// send constructs a decoy registration and sends the encoded request to the decoy completing the
// registration.
func (r *DecoyRegistrar) send(ctx context.Context, cjSession *client.ConjureSession, decoy *pb.TLSDecoySpec, dialError chan error) {

	deadline, deadlineAlreadySet := ctx.Deadline()
	if !deadlineAlreadySet {
		deadline = time.Now().Add(getRandomDuration(deadlineTCPtoDecoyMin, deadlineTCPtoDecoyMax))
	}
	childCtx, childCancelFunc := context.WithDeadline(ctx, deadline)
	defer childCancelFunc()

	//[reference] TCP to decoy
	tcpToDecoyStartTs := time.Now()

	var dial func(ctx context.Context, network, raddr string) (net.Conn, error)
	if cjSession.Dialer != nil {
		dial = func(ctx context.Context, network, raddr string) (net.Conn, error) {
			return cjSession.Dialer(ctx, network, "", raddr)
		}
	} else {
		d := net.Dialer{}
		dial = d.DialContext
	}

	//[Note] decoy.GetIpAddrStr() will get only v4 addr if a decoy has both
	dialConn, err := dial(childCtx, "tcp", decoy.GetIpAddrStr())

	r.setTCPToDecoy(durationToU32ptrMs(time.Since(tcpToDecoyStartTs)))
	if err != nil {
		if opErr, ok := err.(*net.OpError); ok && opErr.Err.Error() == "connect: network is unreachable" {
			dialError <- client.NewRegError(client.Unreachable, err.Error())
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
		dialError <- client.NewRegError(client.TLSError, msg)
		return
	}
	r.setTLSToDecoy(durationToU32ptrMs(time.Since(tlsToDecoyStartTs)))

	//[reference] Create the HTTP request for the registration
	httpRequest, err := r.createRequest(tlsConn, decoy, cjSession)
	if err != nil {
		msg := fmt.Sprintf("%v - %v createReq: %v", decoy.GetHostname(), decoy.GetIpAddrStr(), err.Error())
		dialError <- client.NewRegError(client.TLSError, msg)
		return
	}

	//[reference] Write reg into conn
	_, err = tlsConn.Write(httpRequest)
	if err != nil {
		// This will not get printed because it is executed in a goroutine.
		// Logger().Errorf("%v - %v Could not send Conjure registration request, error: %v", decoy.GetHostname(), decoy.GetIpAddrStr(), err.Error())
		tlsConn.Close()
		msg := fmt.Sprintf("%v - %v Write: %v", decoy.GetHostname(), decoy.GetIpAddrStr(), err.Error())
		dialError <- client.NewRegError(client.TLSError, msg)
		return
	}

	dialError <- nil
	readAndClose(dialConn, time.Second*15)
}

// SelectDecoys - Get an array of `width` decoys to be used for registration
func selectDecoys(sharedSecret []byte, version uint, width uint) ([]*pb.TLSDecoySpec, error) {

	vX := client.IPSupport(version)

	//[reference] prune to v6 only decoys if useV6 is true
	var allDecoys []*pb.TLSDecoySpec
	if vX&client.V6 == client.V6 && vX&client.V4 == client.V4 {
		allDecoys = assets.Assets().GetAllDecoys()
	} else if vX&client.V6 == client.V6 {
		allDecoys = assets.Assets().GetV6Decoys()

	} else if vX&client.V4 == client.V4 {
		allDecoys = assets.Assets().GetV4Decoys()
	} else {
		allDecoys = assets.Assets().GetAllDecoys()
	}

	if len(allDecoys) == 0 {
		return nil, fmt.Errorf("no decoys")
	}

	decoys := make([]*pb.TLSDecoySpec, width)
	numDecoys := big.NewInt(int64(len(allDecoys)))
	hmacInt := new(big.Int)
	idx := new(big.Int)

	//[reference] select decoys
	for i := uint(0); i < width; i++ {
		macString := fmt.Sprintf("registrationdecoy%d", i)
		hmac := core.ConjureHMAC(sharedSecret, macString)
		hmacInt = hmacInt.SetBytes(hmac[:8])
		hmacInt.SetBytes(hmac)
		hmacInt.Abs(hmacInt)
		idx.Mod(hmacInt, numDecoys)
		decoys[i] = allDecoys[int(idx.Int64())]
	}
	return decoys, nil
}
