package utls

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math"
	"net"
	"regexp"

	"github.com/refraction-networking/conjure/pkg/core"
	"github.com/refraction-networking/conjure/pkg/transports"
	pb "github.com/refraction-networking/conjure/proto"
	tls "github.com/refraction-networking/utls"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

const (
	httpPrefixRegexString = ""
	httpPrefixMinLen      = 32
	hmacString            = "UTLSTransportHMACString"
)

const (
	// Earliest client library version ID that supports destination port randomization
	randomizeDstPortMinVersion uint = 3

	// port range boundaries for prefix transport when randomizing
	portRangeMin = 1024
	portRangeMax = 65535
	minTagLength = 32

	defaultPort = 443

	tlsCHPrefix    = "\x16\x03\x01"
	tlsCHHeaderLen = 5
)

// NOTE: using a regex is probably not necessary
var tlsHeaderRegex = regexp.MustCompile(`^\x16\x03\x01(.{2})`)

// Transport provides a struct implementing the Transport, WrappingTransport,
// PortRandomizingTransport, and FixedPortTransport interfaces.
type Transport struct {
	TagObfuscator transports.Obfuscator
	Privkey       [32]byte
}

// New Given a private key this builds the server side transport.
func New(privkey [32]byte) (*Transport, error) {
	return &Transport{
		Privkey:       privkey,
		TagObfuscator: &transports.CTRObfuscator{},
	}, nil
}

// Name returns the human-friendly name of the transport, implementing the
// Transport interface..
func (Transport) Name() string { return "UTLSTransport" }

// LogPrefix returns the prefix used when including this transport in logs,
// implementing the Transport interface.
func (Transport) LogPrefix() string { return "UTLS" }

// GetIdentifier takes in a registration and returns an identifier for it. This
// identifier should be unique for each registration on a given phantom;
// registrations on different phantoms can have the same identifier.
func (Transport) GetIdentifier(d transports.Registration) string {
	return string(core.ConjureHMAC(d.SharedSecret(), hmacString))
}

// GetProto returns the next layer protocol that the transport uses. Implements
// the Transport interface.
func (Transport) GetProto() pb.IPProto {
	return pb.IPProto_Tcp
}

// ParseParams gives the specific transport an option to parse a generic object
// into parameters provided by the client during registration.
func (Transport) ParseParams(libVersion uint, data *anypb.Any) (any, error) {
	if data == nil {
		return nil, nil
	}

	var m = &pb.UTLSTransportParams{}
	err := anypb.UnmarshalTo(data, m, proto.UnmarshalOptions{})
	return m, err
}

// ParamStrings returns an array of tag string that will be added to tunStats when a proxy
// session is closed.
func (Transport) ParamStrings(p any) []string {
	return []string{}
}

// GetDstPort Given the library version, a seed, and a generic object
// containing parameters the transport should be able to return the
// destination port that a clients phantom connection will attempt to reach
func (Transport) GetDstPort(libVersion uint, seed []byte, params any) (uint16, error) {

	if libVersion < randomizeDstPortMinVersion {
		return 0, transports.ErrTransportNotSupported
	}

	if params == nil {
		return defaultPort, nil
	}

	parameters, ok := params.(*pb.GenericTransportParams)
	if !ok {
		return 0, fmt.Errorf("bad parameters provided")
	}

	if parameters.GetRandomizeDstPort() {
		return transports.PortSelectorRange(portRangeMin, portRangeMax, seed)
	}

	return defaultPort, nil
}

func (t Transport) tryFindReg(data *bytes.Buffer, originalDst net.IP, regManager transports.RegManager) (transports.Registration, error) {
	dataLen := data.Len()

	if dataLen == 0 {
		return nil, transports.ErrTryAgain
	} else if dataLen < tlsCHHeaderLen {
		// If we don't have enough bytes to check for the clientHello, check if we can rule it out
		// based on the fixed tls header bytes we expect.
		n := int(math.Min(float64(dataLen), float64(len(tlsCHPrefix))))
		if !bytes.Equal(data.Bytes()[:n], []byte(tlsCHPrefix)[:n]) {
			return nil, transports.ErrNotTransport
		}
		return nil, transports.ErrTryAgain
	}

	// 160301{len:2}{clientHello:len}
	out := tlsHeaderRegex.FindSubmatch(data.Bytes())
	if len(out) < 2 {
		return nil, transports.ErrNotTransport
	}

	// First match is the whole pattern, the second should be the group, and based on the regex it
	// should always be the two bytes that we can parse into a u16 for ClientHello length.
	chLen := binary.BigEndian.Uint16(out[1])
	if dataLen < tlsCHHeaderLen+int(chLen) {
		return nil, transports.ErrTryAgain
	}

	ch := tls.UnmarshalClientHello(data.Bytes()[tlsCHHeaderLen:dataLen])
	if ch == nil {
		// We assume that one MTU is enough for the clientHello. If we have read the declared
		// ClientHello length OR more than 1 MTU and still haven't found our registration then we
		// probably wont find it.
		if dataLen >= tlsCHHeaderLen+int(chLen) || dataLen > 1500 {
			return nil, fmt.Errorf("%w: failed to unmarshal tls", transports.ErrNotTransport)
			// fmt.Printf("failed to read request\n%s\n", err)
		}
		return nil, transports.ErrTryAgain
	}

	obfuscatedID := append(ch.Random, ch.SessionId...)

	hmacID, err := t.TagObfuscator.TryReveal(obfuscatedID, t.Privkey)
	if err != nil || hmacID == nil {
		return nil, transports.ErrNotTransport
	}

	reg, ok := regManager.GetRegistrations(originalDst)[string(hmacID)]
	if !ok {
		return nil, transports.ErrNotTransport
	}

	return reg, nil
}

// WrapConnection attempts to wrap the given connection in the transport. It takes the information
// gathered so far on the connection in data, attempts to identify itself, and if it positively
// identifies itself wraps the connection in the transport, returning a connection that's ready to
// be used by others.
//
// If the returned error is nil or non-nil and non-{ transports.ErrTryAgain,
// transports.ErrNotTransport }, the caller may no longer use data or conn.
func (t Transport) WrapConnection(data *bytes.Buffer, c net.Conn, originalDst net.IP, regManager transports.RegManager) (transports.Registration, net.Conn, error) {
	reg, err := t.tryFindReg(data, originalDst, regManager)
	if err != nil {
		return nil, nil, err
	}

	secret := reg.SharedSecret()

	cert, err := newCertificate(secret)
	config := &tls.Config{
		Certificates:           []tls.Certificate{*cert},
		MinVersion:             tls.VersionTLS10,
		MaxVersion:             tls.VersionTLS12,
		SessionTicketsDisabled: false,
		ClientAuth:             tls.RequireAnyClientCert,
		VerifyConnection:       buildSymmetricVerifier(secret),
		CipherSuites:           []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
	}

	s32 := [32]byte{}
	copy(s32[:], secret)
	config.SetSessionTicketKeys([][32]byte{s32})

	return reg, tls.Server(c, config), err
}

func xorBytes(a, b []byte) []byte {
	if len(a) != len(b) {
		return []byte{}
	}

	n := make([]byte, len(a))
	for i := 0; i < len(a); i++ {
		n[i] = a[i] ^ b[i]
	}

	return n
}

// [X] Fill PSK in client and session cache in station to ensure resumption of legit sessions.
//
// [ ] for TLS 1.2 Use session ticket and encrypt the conjure session ID under the stations pubkey.
//
// [ ] params for uTLS hello id and SNI
//
// [-] Can we leave certs / private keys out if using psk / session resumption? NO
// [X] Alternatively, can we generate the private key dynamically after finding the registration? YES
//
//
// [ ] for TLS 1.3 Use session ticket / PSK:
//    - golang crypto/tls does not implement tls 1.3 PSK resumption, so we would have to add it.
