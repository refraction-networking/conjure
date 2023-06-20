package prefix

import (
	"fmt"
	"io"
	"net"

	"github.com/refraction-networking/conjure/application/transports"
	"github.com/refraction-networking/conjure/pkg/core"
	pb "github.com/refraction-networking/gotapdance/protobuf"
	"google.golang.org/protobuf/proto"
)

// ClientTransport implements the client side transport interface for the Min transport. The
// significant difference is that there is an instance of this structure per client session, where
// the station side Transport struct has one instance to be re-used for all sessions.
type ClientTransport struct {
	// Parameters are fields that will be shared with the station in the registration
	Parameters *pb.PrefixTransportParams

	// // state tracks fields internal to the registrar that survive for the lifetime
	// // of the transport session without being shared - i.e. local derived keys.
	// state any

	Prefix        Prefix
	TagObfuscator transports.Obfuscator

	connectTag       []byte
	stationPublicKey [32]byte
}

// Prefix struct used selected by, or given to the client.
type Prefix struct {
	Bytes []byte
	ID    PrefixID

	// // Function allowing encoding / transformation of obfuscated ID bytes after they have been
	// // obfuscated. Examples - base64 encode, padding
	// [FUTURE WORK]
	// tagEncode() func([]byte) ([]byte, int, error)

	// // Function allowing encoding / transformation of stream bytes after they have been. Examples
	// // - base64 encode, padding
	// [FUTURE WORK]
	// streamEncode() func([]byte) ([]byte, int, error)
}

// DefaultPrefixes provides the prefixes supported by default for use when by the client.
var DefaultPrefixes = []Prefix{}

// Name returns the human-friendly name of the transport, implementing the Transport interface.
func (t *ClientTransport) Name() string {
	return "prefix_" + t.Prefix.ID.Name()
}

// String returns a string identifier for the Transport for logging (including string formatters)
func (t *ClientTransport) String() string {
	return "prefix_" + t.Prefix.ID.Name()
}

// ID provides an identifier that will be sent to the conjure station during the registration so
// that the station knows what transport to expect connecting to the chosen phantom.
func (*ClientTransport) ID() pb.TransportType {
	return pb.TransportType_Prefix
}

// GetParams returns a generic protobuf with any parameters from both the registration and the
// transport.
func (t *ClientTransport) GetParams() proto.Message {
	return t.Parameters
}

// SetParams allows the caller to set parameters associated with the transport, returning an
// error if the provided generic message is not compatible.
func (t *ClientTransport) SetParams(p any) error {
	params, ok := p.(*pb.PrefixTransportParams)
	if !ok {
		return fmt.Errorf("unable to parse params")
	}
	t.Parameters = params

	return nil
}

// GetDstPort returns the destination port that the client should open the phantom connection to
func (t *ClientTransport) GetDstPort(seed []byte, params any) (uint16, error) {
	if t.Parameters == nil || !t.Parameters.GetRandomizeDstPort() {
		return 443, nil
	}

	return transports.PortSelectorRange(portRangeMin, portRangeMax, seed)
}

// Build is specific to the Prefix transport, providing a utility function for building the
// prefix that the client should write to the wire before sending any client bytes.
func (t *ClientTransport) Build() ([]byte, error) {
	// Send hmac(seed, str) bytes to indicate to station (min transport)
	prefix := t.Prefix.Bytes

	obfuscatedID, err := t.TagObfuscator.Obfuscate(t.connectTag, t.stationPublicKey[:])
	if err != nil {
		return nil, err
	}
	return append(prefix, obfuscatedID...), nil
}

// PrepareKeys provides an opportunity for the transport to integrate the station public key
// as well as bytes from the deterministic random generator associated with the registration
// that this ClientTransport is attached to.
func (t *ClientTransport) PrepareKeys(pubkey [32]byte, sharedSecret []byte, hkdf io.Reader) error {
	t.connectTag = core.ConjureHMAC(sharedSecret, "PrefixTransportHMACString")
	t.stationPublicKey = pubkey
	return nil
}

// WrapConn gives the transport the opportunity to perform a handshake and wrap / transform the
// incoming and outgoing bytes send by the implementing client.
func (t *ClientTransport) WrapConn(conn net.Conn) (net.Conn, error) {
	// Send hmac(seed, str) bytes to indicate to station (min transport) generated during Prepare(...)

	// // Send hmac(seed, str) bytes to indicate to station (min transport)
	// connectTag := core.ConjureHMAC(reg.keys.SharedSecret, "PrefixTransportHMACString")

	prefix, err := t.Build()
	if err != nil {
		return nil, fmt.Errorf("failed to build prefix: %w", err)
	}

	_, err = conn.Write(prefix)
	if err != nil {
		return nil, err
	}
	return conn, nil
}
