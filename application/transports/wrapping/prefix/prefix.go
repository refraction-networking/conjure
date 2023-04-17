package prefix

import (
	"bytes"
	"fmt"
	"net"
	"regexp"

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

const minTagLength = 32

// Prefix provides the elements required for independent prefixes to be usable as part of the
// transport.
type Prefix struct {
	// Regular expression to match
	*regexp.Regexp

	// Raw regular expression to parse
	Raw string

	// Static string to match to rule out protocols without using a regex.
	StaticMatch []byte

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
	//Min
	{nil, `.*`, []byte{}, minTagLength, minTagLength, randomizeDstPortMinVersion},
	// HTTP GET
	{nil, `GET / HTTP/1.1\r\n`, []byte("GET / HTTP/1.1\r\n"), 16 + minTagLength, 16 + minTagLength, randomizeDstPortMinVersion},
	// HTTP POST
	{nil, `POST / HTTP/1.1\r\n`, []byte("POST / HTTP/1.1\r\n"), 17 + minTagLength, 17 + minTagLength, randomizeDstPortMinVersion},
	// HTTP Response
	{nil, `HTTP/1.1 200\r\n`, []byte("HTTP/1.1 200\r\n"), 14, 14 + minTagLength, randomizeDstPortMinVersion},
	// TLS Client Hello
	{nil, `\u0016\u0003\u0001\u0040\u0000\u0001`, []byte("\u0016\u0003\u0001\u0040\u0000\u0001"), 6, 6 + minTagLength, randomizeDstPortMinVersion},
	// TLS Server Hello
	{nil, `\u0016\u0003\u0003\u0040\u0000\u0002`, []byte("\u0016\u0003\u0003\u0040\u0000\u0002\r\n"), 6, 6 + minTagLength, randomizeDstPortMinVersion},
	// TLS Alert Warning
	{nil, `\u0015\u0003\u0001\u0000\u0002`, []byte("\u0015\u0003\u0001\u0000\u0002"), 5, 5 + minTagLength, randomizeDstPortMinVersion},
	// TLS Alert Fatal
	{nil, `\u0015\u0003\u0002\u0000\u0002`, []byte("\u0015\u0003\u0002\u0000\u0002"), 5, 5 + minTagLength, randomizeDstPortMinVersion},
	// DNS over TCP
	{nil, `\u0005\u00DC\u005F\u00E0\u0001\u0020`, []byte("\u0005\u00DC\u005F\u00E0\u0001\u0020"), 6, 6 + minTagLength, randomizeDstPortMinVersion},
}

// Transport provides a struct implementing the Transport, WrappingTransport,
// PortRandomizingTransport, and FixedPortTransport interfaces.
type Transport struct {
	SupportedPrefixes []Prefix
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

	hmacID, err := t.tryParsePrefix(data)
	if err != nil {
		return nil, nil, err
	} else if hmacID == "" {
		return nil, nil, transports.ErrNotTransport
	}

	// hmacID := data.String()[:minTagLength]
	reg, ok := regManager.GetRegistrations(originalDst)[hmacID]
	if !ok {
		return nil, nil, transports.ErrNotTransport
	}

	// We don't want the first 32 bytes
	data.Next(minTagLength)

	return reg, transports.PrependToConn(c, data), nil
}

func (t Transport) tryParsePrefix(data *bytes.Buffer) (string, error) {
	return "", transports.ErrTransportNotSupported
}

func init() {
	for _, p := range defaultPrefixes {
		out := Prefix{
			Regexp:      regexp.MustCompile(p.Raw),
			Raw:         p.Raw,
			StaticMatch: p.StaticMatch,
			MinLen:      p.MinLen,
			MaxLen:      p.MaxLen,
			MinVer:      p.MinVer,
		}
		DefaultPrefixes = append(DefaultPrefixes, out)
	}
}
