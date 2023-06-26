package prefix

import (
	"crypto/rand"
	"fmt"
	"io"
	"math/big"
	"net"

	"github.com/refraction-networking/conjure/application/transports"
	"github.com/refraction-networking/conjure/pkg/core"
	pb "github.com/refraction-networking/gotapdance/protobuf"
	"google.golang.org/protobuf/proto"
)

// ClientTransport implements the client side transport interface for the Min transport. The
// significant difference is that there is an instance of this structure per client session, where
// the station side Transport struct has one instance to be re-used for all sessions.
//
// External libraries must set parameters through SetParams using PrefixTransportParams.
type ClientTransport struct {
	parameters *pb.PrefixTransportParams

	// // state tracks fields internal to the registrar that survive for the lifetime
	// // of the transport session without being shared - i.e. local derived keys.
	// state any

	Prefix        Prefix
	TagObfuscator transports.Obfuscator

	connectTag       []byte
	stationPublicKey [32]byte
}

// ClientParams are parameters avaialble to configure the Prefix transport
// outside of the specific Prefix
type ClientParams struct {
	RandomizeDstPort bool
}

// Prefix struct used by, selected by, or given to the client. This interface allows for non-uniform
// behavior like a rand prefix for example.
type Prefix interface {
	Bytes() []byte
	ID() PrefixID
	DstPort([]byte) uint16
}

// DefaultPrefixes provides the prefixes supported by default for use when by the client.
var DefaultPrefixes = map[PrefixID]Prefix{}

// Name returns the human-friendly name of the transport, implementing the Transport interface.
func (t *ClientTransport) Name() string {
	if t.Prefix == nil {
		return "prefix"
	}
	return "prefix_" + t.Prefix.ID().Name()
}

// String returns a string identifier for the Transport for logging (including string formatters)
func (t *ClientTransport) String() string {
	return t.Name()
}

// ID provides an identifier that will be sent to the conjure station during the registration so
// that the station knows what transport to expect connecting to the chosen phantom.
func (*ClientTransport) ID() pb.TransportType {
	return pb.TransportType_Prefix
}

// GetParams returns a generic protobuf with any parameters from both the registration and the
// transport.
func (t *ClientTransport) GetParams() (proto.Message, error) {
	if t == nil {
		return nil, ErrBadParams
	}

	if t.Prefix == nil {
		return nil, fmt.Errorf("%w: empty or invalid Prefix provided", ErrBadParams)
	}

	if t.parameters == nil {
		id := int32(t.Prefix.ID())
		F := false
		t.parameters = &pb.PrefixTransportParams{
			PrefixId:         &id,
			RandomizeDstPort: &F,
		}
	}

	return t.parameters, nil
}

// SetParams allows the caller to set parameters associated with the transport, returning an
// error if the provided generic message is not compatible or the parameters are otherwise invalid
func (t *ClientTransport) SetParams(p any) error {
	prefixParams, ok := p.(*pb.PrefixTransportParams)
	if !ok {
		return ErrBadParams
	}

	if prefixParams == nil {
		return ErrBadParams
	}

	if prefix, ok := DefaultPrefixes[PrefixID(prefixParams.GetPrefixId())]; ok {
		t.Prefix = prefix
		t.parameters = prefixParams

		// clear the prefix if it was set. this is used for RegResponse only.
		t.parameters.Prefix = []byte{}
		return nil
	}

	if prefixParams.GetPrefixId() == int32(Rand) {
		newPrefix, err := pickRandomPrefix(rand.Reader)
		if err != nil {
			return err
		}

		t.Prefix = newPrefix

		if t.parameters == nil {
			t.parameters = &pb.PrefixTransportParams{}
		}

		id := int32(t.Prefix.ID())
		t.parameters.PrefixId = &id
		t.parameters.RandomizeDstPort = prefixParams.RandomizeDstPort

		return nil
	}

	return ErrUnknownPrefix
}

// GetDstPort returns the destination port that the client should open the phantom connection to
func (t *ClientTransport) GetDstPort(seed []byte) (uint16, error) {

	if t == nil {
		return 0, ErrBadParams
	}

	if t.Prefix == nil {
		return 0, fmt.Errorf("%w: empty or invalid Prefix provided", ErrBadParams)
	}

	prefixID := t.Prefix.ID()

	if prefixID == Rand {
		return 0, fmt.Errorf("%w: use SetParams or FromID if using Rand prefix", ErrUnknownPrefix)
	}

	if t.parameters == nil {
		p := int32(prefixID)
		t.parameters = &pb.PrefixTransportParams{PrefixId: &p}
	}

	if t.parameters.GetRandomizeDstPort() {
		return transports.PortSelectorRange(portRangeMin, portRangeMax, seed)
	}

	return t.Prefix.DstPort(seed), nil
}

// Build is specific to the Prefix transport, providing a utility function for building the
// prefix that the client should write to the wire before sending any client bytes.
func (t *ClientTransport) Build() ([]byte, error) {
	if t.Prefix == nil {
		return nil, ErrBadParams
	}

	// Send hmac(seed, str) bytes to indicate to station (min transport)
	prefix := t.Prefix.Bytes()

	if t.TagObfuscator == nil {
		t.TagObfuscator = transports.CTRObfuscator{}
	}
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

// ---

type clientPrefix struct {
	bytes []byte
	id    PrefixID
	port  uint16

	// // Function allowing encoding / transformation of obfuscated ID bytes after they have been
	// // obfuscated. Examples - base64 encode, padding
	// [FUTURE WORK]
	// tagEncode() func([]byte) ([]byte, int, error)

	// // Function allowing encoding / transformation of stream bytes after they have been. Examples
	// // - base64 encode, padding
	// [FUTURE WORK]
	// streamEncode() func([]byte) ([]byte, int, error)
}

func (c *clientPrefix) Bytes() []byte {
	return c.bytes
}

func (c *clientPrefix) ID() PrefixID {
	return c.id
}

func (c *clientPrefix) DstPort([]byte) uint16 {
	return c.port
}

// ---

// TryFromID returns a Prefix based on the Prefix ID. This is useful for non-static prefixes like the
// random prefix
func TryFromID(id PrefixID) (Prefix, error) {

	if len(DefaultPrefixes) == 0 || id < Rand || int(id) > len(DefaultPrefixes) {
		return nil, ErrUnknownPrefix
	}

	if id == Rand {
		return pickRandomPrefix(rand.Reader)
	}

	return DefaultPrefixes[id], nil
}

func pickRandomPrefix(r io.Reader) (Prefix, error) {
	var n = big.NewInt(int64(len(DefaultPrefixes)))
	i, err := rand.Int(r, n)
	if err != nil {
		return nil, err
	}

	return DefaultPrefixes[PrefixID(i.Int64())], nil
}
