package interfaces

import (
	"context"
	"io"
	"net"

	pb "github.com/refraction-networking/conjure/proto"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

// Registrar defines the interface for a module completing the initial portion of the conjure
// protocol which registers the clients intent to connect, along with the specifics of the session
// they wish to establish.
type Registrar interface {
	Register(context.Context, any) (any, error)

	// PrepareRegKeys prepares key materials specific to the registrar
	PrepareRegKeys(pubkey [32]byte) error
}

// DialFunc is a function type alias for dialing a connection.
type DialFunc = func(ctx context.Context, network, laddr, raddr string) (net.Conn, error)

// Transport provides a generic interface for utilities that allow the client to dial and connect to
// a phantom address when creating a Conjure connection.
type Transport interface {
	// Name returns a string identifier for the Transport for logging
	Name() string
	// String returns a string identifier for the Transport for logging (including string formatters)
	String() string

	// ID provides an identifier that will be sent to the conjure station during the registration so
	// that the station knows what transport to expect connecting to the chosen phantom.
	ID() pb.TransportType

	// GetParams returns a generic protobuf with any parameters from both the registration and the
	// transport.
	GetParams() (proto.Message, error)

	// ParseParams gives the specific transport an option to parse a generic object into parameters
	// provided by the station in the registration response during registration.
	ParseParams(data *anypb.Any) (any, error)

	// SetParams allows the caller to set parameters associated with the transport, returning an
	// error if the provided generic message is not compatible. the variadic bool parameter is used
	// to indicate whether the client should sanity check the params or just apply them. This is
	// useful in cases where the registrar may provide options to the client that it is able to
	// handle, but are outside of the clients sanity checks. (see prefix transport for an example)
	SetParams(any, ...bool) error

	// Prepare lets the transport use the dialer to prepare. This is called before GetParams to let the
	// transport prepare stuff such as nat traversal.
	Prepare(ctx context.Context, dialer func(ctx context.Context, network, laddr, raddr string) (net.Conn, error)) error

	// GetDstPort returns the destination port that the client should open the phantom connection with.
	GetDstPort(seed []byte) (uint16, error)

	// PrepareKeys provides an opportunity for the transport to integrate the station public key
	// as well as bytes from the deterministic random generator associated with the registration
	// that this ClientTransport is attached to.
	PrepareKeys(pubkey [32]byte, sharedSecret []byte, dRand io.Reader) error
}

// WrappingTransport defines the interface for reactive transports that receive and then wrap
// client connections from the station perspective.
type WrappingTransport interface {
	Transport

	// Connect returns a net.Conn connection given a context and ConjureReg
	WrapConn(conn net.Conn) (net.Conn, error)
}

// ConnectingTransport defines the interface for proactive transports that dial out from the station
// as a means of creating the proxy connection with the client.
type ConnectingTransport interface {
	Transport

	WrapDial(dialer DialFunc) (DialFunc, error)

	DisableRegDelay() bool
}

// Registration is a generic interface for the registration structure used by clients to establish
// a connection after registering their session with the station. This acts as a kind of ticket,
// holding the information necessary to (re-)establish the connection to the phantom.
type Registration interface{}
