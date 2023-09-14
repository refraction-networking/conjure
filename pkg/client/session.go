package client

import (
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/refraction-networking/conjure/pkg/core"
	"github.com/refraction-networking/conjure/pkg/core/interfaces"
	"github.com/refraction-networking/conjure/pkg/log"
	pb "github.com/refraction-networking/conjure/proto"
	"google.golang.org/protobuf/proto"
)

var sessionsTotal atomic.Uint64

// Simple type alias for brevity
type dialFunc = func(ctx context.Context, network, laddr, raddr string) (net.Conn, error)

// ConjureSession - Create a session with details for registration and connection
type ConjureSession struct {
	Keys           *core.SharedKeys
	V6Support      IPSupport
	UseProxyHeader bool
	SessionID      uint64
	Phantom        *net.IP
	Transport      interfaces.Transport
	CovertAddress  string
	// rtt			   uint // tracked in stats

	DisableRegistrarOverrides bool

	// TcpDialer allows the caller to provide a custom dialer for outgoing proxy connections.
	//
	// THIS IS REQUIRED TO INTERFACE WITH PSIPHON ANDROID
	//		we use their dialer to prevent connection loopback into our own proxy
	//		connection when tunneling the whole device.
	Dialer dialFunc

	// RegDelay is the delay duration to wait for registration ingest.
	RegDelay time.Duration

	// performance tracking
	stats *pb.SessionStats
}

// MakeConjureSessionSilent creates a conjure session without logging anything
func MakeConjureSessionSilent(covert string, transport interfaces.Transport) *ConjureSession {
	keys, err := core.GenerateClientSharedKeys(getStationKey())

	if err != nil {
		return nil
	}
	//[TODO]{priority:NOW} move v6support initialization to assets so it can be tracked across dials
	cjSession := &ConjureSession{
		Keys:                      keys,
		V6Support:                 V4 | V6,
		UseProxyHeader:            false,
		Transport:                 transport,
		CovertAddress:             covert,
		SessionID:                 sessionsTotal.Add(1),
		DisableRegistrarOverrides: false,
	}

	return cjSession
}

func LogConjureSession(cjSession *ConjureSession) {

	keys := cjSession.Keys

	sharedSecretStr := make([]byte, hex.EncodedLen(len(keys.SharedSecret)))
	hex.Encode(sharedSecretStr, keys.SharedSecret)
	log.Debugf("%v Shared Secret  - %s", cjSession.IDString(), sharedSecretStr)

	log.Debugf("%v covert %s", cjSession.IDString(), cjSession.CovertAddress)

	reprStr := make([]byte, hex.EncodedLen(len(keys.Representative)))
	hex.Encode(reprStr, keys.Representative)
	log.Debugf("%v Representative - %s", cjSession.IDString(), reprStr)

}

func MakeConjureSession(covert string, transport interfaces.Transport) *ConjureSession {

	cjSession := MakeConjureSessionSilent(covert, transport)
	if cjSession == nil {
		return nil
	}

	// Print out the session details (debug)
	LogConjureSession(cjSession)

	return cjSession
}

func FindConjureSessionInRange(covert string, transport interfaces.Transport, phantomSubnet *net.IPNet) *ConjureSession {

	count := 0
	log.Debugf("Searching for a seed for phantom subnet %v...", phantomSubnet)
	for count < 100000 {
		// Generate a random session
		cjSession := MakeConjureSessionSilent(covert, transport)
		count += 1

		// Get the phantoms this seed would generate
		phantom4, phantom6, _, err := SelectPhantom(cjSession.Keys.ConjureSeed, cjSession.V6Support)
		if err != nil {
			log.Warnf("%v failed to select Phantom: %v", cjSession.IDString(), err)
		}

		// See if our phantoms are in the subnet
		if phantomSubnet.Contains(*phantom4) || phantomSubnet.Contains(*phantom6) {
			log.Debugf("Generated %d sessions to find one in %v", count, phantomSubnet)
			// Print out what we got
			LogConjureSession(cjSession)

			return cjSession
		}
	}
	log.Warnf("Failed to find a session in %v", phantomSubnet)
	return nil
}

// IDString - Get the ID string for the session
func (cjSession *ConjureSession) IDString() string {
	if cjSession.Keys == nil || cjSession.Keys.SharedSecret == nil {
		return fmt.Sprintf("[%v-000000]", strconv.FormatUint(cjSession.SessionID, 10))
	}

	secret := make([]byte, hex.EncodedLen(len(cjSession.Keys.SharedSecret)))
	n := hex.Encode(secret, cjSession.Keys.SharedSecret)
	if n < 6 {
		return fmt.Sprintf("[%v-000000]", strconv.FormatUint(cjSession.SessionID, 10))
	}
	return fmt.Sprintf("[%v-%s]", strconv.FormatUint(cjSession.SessionID, 10), secret[:6])
}

// String - Print the string for debug and/or logging
func (cjSession *ConjureSession) String() string {
	return cjSession.IDString()
	// expand for debug??
}

// conjureReg generates ConjureReg from the corresponding ConjureSession
func (cjSession *ConjureSession) conjureReg() *ConjureReg {
	return &ConjureReg{
		ConjureSession: cjSession,
		v6Support:      cjSession.V6Support,
		covertAddress:  cjSession.CovertAddress,
		Transport:      cjSession.Transport,
		Dialer:         removeLaddr(cjSession.Dialer),
		useProxyHeader: cjSession.UseProxyHeader,
	}
}

// BidirectionalRegData returns a C2SWrapper for bidirectional registration
func (cjSession *ConjureSession) BidirectionalRegData(regSource *pb.RegistrationSource) (*ConjureReg, *pb.C2SWrapper, error) {
	reg := cjSession.conjureReg()

	c2s, err := reg.generateClientToStation()
	if err != nil {
		return nil, nil, err
	}

	return reg, &pb.C2SWrapper{
		SharedSecret:        cjSession.Keys.SharedSecret,
		RegistrationPayload: c2s,
		RegistrationSource:  regSource,
	}, nil

}

// UnidirectionalRegData returns a C2SWrapper for unidirectional registration
func (cjSession *ConjureSession) UnidirectionalRegData(regSource *pb.RegistrationSource) (*ConjureReg, *pb.C2SWrapper, error) {
	reg := cjSession.conjureReg()

	phantom4, phantom6, supportRandomPort, err := SelectPhantom(cjSession.Keys.ConjureSeed, cjSession.V6Support)
	if err != nil {
		log.Warnf("%v failed to select Phantom: %v", cjSession.IDString(), err)
		return nil, nil, err
	}

	reg.phantom4 = phantom4
	reg.phantom6 = phantom6
	err = cjSession.Transport.SetParams(&pb.GenericTransportParams{RandomizeDstPort: proto.Bool(supportRandomPort)}, true)
	if err != nil {
		return nil, nil, err
	}
	reg.phantomDstPort, err = cjSession.Transport.GetDstPort(reg.Keys.ConjureSeed)
	if err != nil {
		return nil, nil, err
	}

	c2s, err := reg.generateClientToStation()
	if err != nil {
		return nil, nil, err
	}

	return reg, &pb.C2SWrapper{
		SharedSecret:        cjSession.Keys.SharedSecret,
		RegistrationPayload: c2s,
		RegistrationSource:  regSource,
	}, nil
}

// GetV6Support created for the sake of removing ConjureReg
func (cjSession *ConjureSession) GetV6Support() *bool {
	support := true
	if cjSession.V6Support&V6 == 0 {
		support = false
	}
	return &support
}

// GetV4Support created for the sake of removing ConjureReg
func (cjSession *ConjureSession) GetV4Support() *bool {
	// for now return true and register both
	support := true
	if cjSession.V6Support&V4 == 0 {
		support = false
	}
	return &support
}

type resultTuple struct {
	conn net.Conn
	err  error
}
