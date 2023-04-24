package prefix

import (
	"bytes"
	"fmt"
	"net"

	dd "github.com/refraction-networking/conjure/application/lib"
	"github.com/refraction-networking/conjure/application/transports"
	pb "github.com/refraction-networking/gotapdance/protobuf"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

const (
	// Earliest client library version ID that supports destination port randomization
	randomizeDstPortMinVersion uint = 3

	// port range boundaries for prefix transport when randomizing
	portRangeMin = 1024
	portRangeMax = 65535
)

const minTagLength = 64

// Prefix provides the elements required for independent prefixes to be usable as part of the
// transport.
type Prefix struct {
	// // Regular expression to match
	// *regexp.Regexp

	// Function allowing decode / transformation of obfuscated ID bytes before attempting to
	// de-obfuscate them. Example - base64 decode.
	fn func([]byte) ([]byte, error)

	// Static string to match to rule out protocols without using a regex.
	StaticMatch []byte

	// Offset in a byte array where we expect the identifier to start.
	Offset int

	// Minimum length to guarantee we have received the whole identifier
	// (i.e. return ErrTryAgain)
	MinLen int

	// Maximum length after which we can rule out prefix if we have not found a known identifier
	// (i.e. return ErrNotTransport)
	MaxLen int

	// Minimum client library version that supports this prefix
	MinVer uint
}

// DefaultPrefixes provides the prefixes supported by default for use when
// initializing the prefix transport.
var DefaultPrefixes = []Prefix{}
var defaultPrefixes = []Prefix{
	// HTTP GET
	{nil, []byte("GET / HTTP/1.1\r\n"), 16, 16 + minTagLength, 16 + minTagLength, randomizeDstPortMinVersion},
	// HTTP POST
	{nil, []byte("POST / HTTP/1.1\r\n"), 17, 17 + minTagLength, 17 + minTagLength, randomizeDstPortMinVersion},
	// HTTP Response
	{nil, []byte("HTTP/1.1 200\r\n"), 14, 14 + minTagLength, 14 + minTagLength, randomizeDstPortMinVersion},
	// TLS Client Hello
	{nil, []byte("\x16\x03\x01\x40\x00\x01"), 6, 6 + minTagLength, 6 + minTagLength, randomizeDstPortMinVersion},
	// TLS Server Hello
	{nil, []byte("\x16\x03\x03\x40\x00\x02\r\n"), 8, 8 + minTagLength, 8 + minTagLength, randomizeDstPortMinVersion},
	// TLS Alert Warning
	{nil, []byte("\x15\x03\x01\x00\x02"), 5, 5 + minTagLength, 5 + minTagLength, randomizeDstPortMinVersion},
	// TLS Alert Fatal
	{nil, []byte("\x15\x03\x02\x00\x02"), 5, 5 + minTagLength, 5 + minTagLength, randomizeDstPortMinVersion},
	// DNS over TCP
	{nil, []byte("\x05\xDC\x5F\xE0\x01\x20"), 6, 6 + minTagLength, 6 + minTagLength, randomizeDstPortMinVersion},
	// SSH-2.0-OpenSSH_8.9p1
	{nil, []byte("SSH-2.0-OpenSSH_8.9p1"), 21, 21 + minTagLength, 21 + minTagLength, randomizeDstPortMinVersion},
	//Min - Empty prefix
	{nil, []byte{}, 0, minTagLength, minTagLength, randomizeDstPortMinVersion},
}

// Transport provides a struct implementing the Transport, WrappingTransport,
// PortRandomizingTransport, and FixedPortTransport interfaces.
type Transport struct {
	SupportedPrefixes []Prefix
	tagObfuscator     transports.Obfuscator
	privkey           [32]byte
}

// Name returns the human-friendly name of the transport, implementing the
// Transport interface..
func (Transport) Name() string { return "PrefixTransport" }

// LogPrefix returns the prefix used when including this transport in logs,
// implementing the Transport interface.
func (Transport) LogPrefix() string { return "PREF" }

// GetIdentifier takes in a registration and returns an identifier for it. This
// identifier should be unique for each registration on a given phantom;
// registrations on different phantoms can have the same identifier.
func (Transport) GetIdentifier(d *dd.DecoyRegistration) string {
	return string(d.Keys.ConjureHMAC("PrefixTransportHMACString"))
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

	// For backwards compatibility we create a generic transport params object
	// for transports that existed before the transportParams fields existed.
	if libVersion < randomizeDstPortMinVersion {
		f := false
		return &pb.GenericTransportParams{
			RandomizeDstPort: &f,
		}, nil
	}

	var m = &pb.GenericTransportParams{}
	err := anypb.UnmarshalTo(data, m, proto.UnmarshalOptions{})
	return m, err
}

// GetDstPort Given the library version, a seed, and a generic object
// containing parameters the transport should be able to return the
// destination port that a clients phantom connection will attempt to reach
func (Transport) GetDstPort(libVersion uint, seed []byte, params any) (uint16, error) {

	if libVersion < randomizeDstPortMinVersion {
		return 443, nil
	}

	if params == nil {
		return 443, nil
	}

	parameters, ok := params.(*pb.GenericTransportParams)
	if !ok {
		return 0, fmt.Errorf("bad parameters provided")
	}

	if parameters.GetRandomizeDstPort() {
		return transports.PortSelectorRange(portRangeMin, portRangeMax, seed)
	}

	return 443, nil
}

// WrapConnection attempts to wrap the given connection in the transport. It
// takes the information gathered so far on the connection in data, attempts to
// identify itself, and if it positively identifies itself wraps the connection
// in the transport, returning a connection that's ready to be used by others.
//
// If the returned error is nil or non-nil and non-{ transports.ErrTryAgain,
// transports.ErrNotTransport }, the caller may no longer use data or conn.
func (t Transport) WrapConnection(data *bytes.Buffer, c net.Conn, originalDst net.IP, regManager *dd.RegistrationManager) (*dd.DecoyRegistration, net.Conn, error) {
	if data.Len() < minTagLength {
		return nil, nil, transports.ErrTryAgain
	}

	reg, err := t.tryFindReg(data, originalDst, regManager)
	if err != nil {
		return nil, nil, err
	}

	return reg, transports.PrependToConn(c, data), nil
}

func (t Transport) tryFindReg(data *bytes.Buffer, originalDst net.IP, regManager *dd.RegistrationManager) (*dd.DecoyRegistration, error) {
	if data.Len() == 0 {
		return nil, transports.ErrTryAgain
	}

	err := transports.ErrNotTransport
	for _, prefix := range t.SupportedPrefixes {
		if len(prefix.StaticMatch) > 0 {
			matchLen := min(len(prefix.StaticMatch), data.Len())
			if !bytes.Equal(prefix.StaticMatch[:matchLen], data.Bytes()[:matchLen]) {
				continue
			}
		}

		if data.Len() < prefix.MinLen {
			// the data we have received matched at least one static prefix, but was not long
			// enough to extract the tag - go back and read more, continue checking if any
			// of the other prefixes match. If not we want to indicate to read more, not
			// give up because we may receive the rest of the match.
			err = transports.ErrTryAgain
			continue
		}

		if data.Len() < prefix.Offset+minTagLength && data.Len() < prefix.MaxLen {
			err = transports.ErrTryAgain
			continue
		} else if data.Len() < prefix.MaxLen {
			continue
		}

		var obfuscatedID []byte
		if prefix.fn != nil {
			obfuscatedID, err = prefix.fn(data.Bytes()[prefix.Offset:])
			if err != nil || len(obfuscatedID) != minTagLength {
				continue
			}
		} else {
			obfuscatedID = data.Bytes()[prefix.Offset : prefix.Offset+minTagLength]
		}
		// fmt.Printf("err: %s, id: %s\n", err, hex.EncodeToString(obfuscatedID))

		hmacID, err := t.tagObfuscator.TryReveal(obfuscatedID, t.privkey)
		if err != nil || hmacID == nil {
			continue
		}

		reg, ok := regManager.GetRegistrations(originalDst)[string(hmacID)]
		if !ok {
			continue
		}

		// We don't want the first 32 bytes
		data.Next(prefix.Offset + minTagLength)

		return reg, nil
	}

	return nil, err
}

func init() {
	// if at any point we need to do init on the prefixes (i.e compiling regular expressions) it
	// should happen here.
	DefaultPrefixes = defaultPrefixes
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
