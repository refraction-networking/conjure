package interfaces

import (
	"bytes"
	"context"
	"io"
	"net"

	pb "github.com/refraction-networking/conjure/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

// RegistrationSS provides an abstraction around station tracked registrations.
type RegistrationSS interface {
	SharedSecret() []byte
	GetRegistrationAddress() string
	GetSrcPort() uint16
	GetDstPort() uint16
	PhantomIP() *net.IP

	// Transport management functions
	TransportType() pb.TransportType
	TransportParams() any
	SetTransportKeys(interface{}) error
	TransportKeys() interface{}
	TransportReader() io.Reader
}

// RegManager provides an abstraction for the RegistrationManager which tracks registrations.
type RegManager interface {
	GetRegistrations(phantomAddr net.IP) map[string]RegistrationSS
}

// TransportSS defines the interface for the manager to interface with variable transports that wrap
// the traffic sent by clients.
type TransportSS interface {
	// The human-friendly name of the transport.
	Name() string

	// The prefix used when including this transport in logs.
	LogPrefix() string

	// GetIdentifier takes in a registration and returns an identifier for it. This identifier
	// should be unique for each registration on a given phantom; registrations on different
	// phantoms can have the same identifier.
	GetIdentifier(RegistrationSS) string

	// GetProto returns the IP protocol used by the transport. Typical transports will use TCP or
	// UDP, if something beyond these is required you will need to update the enum in the protobuf
	// file and change the packet processing in the detector.
	GetProto() pb.IPProto

	// GetDstPort Given the library version, a seed, and a generic object containing parameters the
	// transport should be able to return the destination port that a clients phantom connection
	// will attempt to reach. The libVersion is provided incase of version dependent changes in the
	// transports port selection algorithm.
	GetDstPort(libVersion uint, seed []byte, parameters any) (uint16, error)

	// ParseParams gives the specific transport an option to parse a generic object into parameters
	// provided by the client during registration. The libVersion is provided incase of version
	// dependent changes in the transport params or param parsing.
	ParseParams(libVersion uint, data *anypb.Any) (any, error)

	// ParamStrings returns an array of tag string that will be added to tunStats when a proxy
	// session is closed.
	ParamStrings(p any) []string
}

// WrappingTransportSS describes any transport that is able to passively
// listen to incoming network connections and identify itself, then actively
// wrap the connection.
type WrappingTransportSS interface {
	TransportSS

	// WrapConnection attempts to wrap the given connection in the transport. It takes the
	// information gathered so far on the connection in data, attempts to identify itself, and if it
	// positively identifies itself wraps the connection in the transport, returning a connection
	// that's ready to be used by others.
	//
	// If the returned error is nil or non-nil and non-{ transports.ErrTryAgain,
	// transports.ErrNotTransport }, the caller may no longer use data or conn.
	//
	// Implementations should not Read from conn unless they have positively identified that the
	// transport exists and are in the process of wrapping the connection.
	//
	// Implementations should not Read from data unless they are are attempting to wrap the
	// connection. Use data.Bytes() to get all of the data that has been seen on the connection.
	//
	// If implementations cannot tell if the transport exists on the connection (e.g. there hasn't
	// yet been enough data sent to be conclusive), they should return transports.ErrTryAgain. If
	// the transport can be conclusively determined to not exist on the connection, implementations
	// should return transports.ErrNotTransport.
	WrapConnection(data *bytes.Buffer, conn net.Conn, phantom net.IP, rm RegManager) (reg RegistrationSS, wrapped net.Conn, err error)
}

// ConnectingTransportSS describes transports that actively form an outgoing connection to clients to
// initiate the conversation.
type ConnectingTransportSS interface {
	TransportSS

	// Connect attempts to connect to the client from the phantom address derived in the
	// registration.
	Connect(context.Context, RegistrationSS) (net.Conn, error)
}

// RegOverride provides a generic way for the station to mutate an incoming registration before
// handing it off to the stations or returning it to the client as part of the RegResponse protobuf.
type RegOverride interface {
	Override(*pb.C2SWrapper, io.Reader) error
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

// DNAT used by the station side DTLS transport implementation to warm up the DNAT table such that
// we are able to handle incoming client connections.
type DNAT interface {
	AddEntry(clientAddr *net.IP, clientPort uint16, phantomIP *net.IP, phantomPort uint16) error
}

// DnatBuilder function type alias for building a DNAT object
type DnatBuilder func() (DNAT, error)
