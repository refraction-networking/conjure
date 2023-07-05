package interfaces

import (
	"io"
	"net"

	pb "github.com/refraction-networking/conjure/proto"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

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

	// GetDstPort returns the destination port that the client should open the phantom connection with.
	GetDstPort(seed []byte) (uint16, error)

	// PrepareKeys provides an opportunity for the transport to integrate the station public key
	// as well as bytes from the deterministic random generator associated with the registration
	// that this ClientTransport is attached to.
	PrepareKeys(pubkey [32]byte, sharedSecret []byte, dRand io.Reader) error

	// Connect returns a net.Conn connection given a context and ConjureReg
	WrapConn(conn net.Conn) (net.Conn, error)
}

// Overrides makes it possible to treat an array of overrides as a single override note that the
// subsequent overrides are not aware of those that come before so they may end up undoing their
// changes.
type Overrides []RegOverride

// Override implements the RegOverride interface.
func (o Overrides) Override(reg *pb.C2SWrapper, randReader io.Reader) error {
	var err error
	for _, override := range o {
		err = override.Override(reg, randReader)
		if err != nil {
			return err
		}
	}
	return nil
}

// RegOverride provides a generic way for the station to mutate an incoming registration before
// handing it off to the stations or returning it to the client as part of the RegResponse protobuf.
type RegOverride interface {
	Override(*pb.C2SWrapper, io.Reader) error
}
