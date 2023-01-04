package min

import (
	"bytes"
	"net"

	dd "github.com/refraction-networking/conjure/application/lib"
	"github.com/refraction-networking/conjure/application/transports"
	pb "github.com/refraction-networking/gotapdance/protobuf"
)

const minTagLength = 32

// Transport provides a struct implementing the Transport, WrappingTransport,
// PortRandomizingTransport, and FixedPortTransport interfaces.
type Transport struct{}

// Name returns the human-friendly name of the transport, implementing the
// Transport interface..
func (Transport) Name() string { return "MinTransport" }

// LogPrefix returns the prefix used when including this transport in logs,
// implementing the Transport interface.
func (Transport) LogPrefix() string { return "MIN" }

// GetIdentifier takes in a registration and returns an identifier for it. This
// identifier should be unique for each registration on a given phantom;
// registrations on different phantoms can have the same identifier. ,
// implementing the Transport interface.
func (Transport) GetIdentifier(d *dd.DecoyRegistration) string {
	return string(d.Keys.ConjureHMAC("MinTransportHMACString"))
}

// GetProto returns the next layer protocol that the transport uses. Implements
// the Transport interface.
func (Transport) GetProto() pb.IpProto {
	return pb.IpProto_Tcp
}

// WrapConnection attempts to wrap the given connection in the transport. It
// takes the information gathered so far on the connection in data, attempts to
// identify itself, and if it positively identifies itself wraps the connection
// in the transport, returning a connection that's ready to be used by others.
//
// If the returned error is nil or non-nil and non-{ transports.ErrTryAgain,
// transports.ErrNotTransport }, the caller may no longer use data or conn.
func (Transport) WrapConnection(data *bytes.Buffer, c net.Conn, originalDst net.IP, regManager *dd.RegistrationManager) (*dd.DecoyRegistration, net.Conn, error) {
	if data.Len() < minTagLength {
		return nil, nil, transports.ErrTryAgain
	}

	hmacID := data.String()[:minTagLength]
	reg, ok := regManager.GetRegistrations(originalDst)[hmacID]
	if !ok {
		return nil, nil, transports.ErrNotTransport
	}

	// We don't want the first 32 bytes
	data.Next(minTagLength)

	return reg, transports.PrependToConn(c, data), nil
}

// ServicePort returns the fixed port that the transport uses. Implements the
// FixedPortTransport interface for transports.
func (Transport) ServicePort() uint16 {
	return 443
}

const (
	portRangeMin = 1024
	portRangeMax = 65535
)

// GetPortSelector returns a port selector created for this specific type of
// Transport.
func (Transport) GetPortSelector() func([]byte, any) (uint16, error) {
	return transports.PortSelectorRange(portRangeMin, portRangeMax)
}
