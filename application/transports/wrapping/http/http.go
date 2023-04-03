package http

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"

	dd "github.com/refraction-networking/conjure/application/lib"
	"github.com/refraction-networking/conjure/application/transports"
	pb "github.com/refraction-networking/gotapdance/protobuf"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

const (
	httpPrefixRegexString = ""
	httpPrefixMinLen      = 32
	hmacString            = "HTTPTransportHMACString"
)

const (
	// Earliest client library version ID that supports destination port randomization
	randomizeDstPortMinVersion uint = 3

	// port range boundaries for prefix transport when randomizing
	portRangeMin = 1024
	portRangeMax = 65535
	minTagLength = 32

	defaultPort = 80
)

// Transport provides a struct implementing the Transport, WrappingTransport,
// PortRandomizingTransport, and FixedPortTransport interfaces.
type Transport struct{}

// Name returns the human-friendly name of the transport, implementing the
// Transport interface..
func (Transport) Name() string { return "HTTPTransport" }

// LogPrefix returns the prefix used when including this transport in logs,
// implementing the Transport interface.
func (Transport) LogPrefix() string { return "HTTP" }

// GetIdentifier takes in a registration and returns an identifier for it. This
// identifier should be unique for each registration on a given phantom;
// registrations on different phantoms can have the same identifier.
func (Transport) GetIdentifier(d *dd.DecoyRegistration) string {
	return string(d.Keys.ConjureHMAC(hmacString))
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

// WrapConnection attempts to wrap the given connection in the transport. It
// takes the information gathered so far on the connection in data, attempts to
// identify itself, and if it positively identifies itself wraps the connection
// in the transport, returning a connection that's ready to be used by others.
//
// If the returned error is nil or non-nil and non-{ transports.ErrTryAgain,
// transports.ErrNotTransport }, the caller may no longer use data or conn.
func (t *Transport) WrapConnection(data *bytes.Buffer, c net.Conn, originalDst net.IP, regManager *dd.RegistrationManager) (*dd.DecoyRegistration, net.Conn, error) {
	dataLen := data.Len()

	if dataLen == 0 {
		return nil, nil, transports.ErrTryAgain
	}

	req, err := http.ReadRequest(bufio.NewReader(data))
	if err != nil {
		// fmt.Printf("failed to read request\n%s\n", err)
		return nil, nil, transports.ErrNotTransport
	}

	hmacIDStr := req.Header.Get("X-Ignore")
	if hmacIDStr == "" {
		return nil, nil, transports.ErrNotTransport
	}
	hmacID, err := base64.StdEncoding.DecodeString(hmacIDStr)
	if err != nil {
		return nil, nil, transports.ErrNotTransport
	}

	reg, ok := regManager.GetRegistrations(originalDst)[string(hmacID)]
	if !ok {
		return nil, nil, transports.ErrNotTransport
	}

	if req.ContentLength > 0 {
		// buf := make([]byte, req.ContentLength)
		// _, err := io.ReadFull(req.Body, buf)
		// if err != nil {
		// 	// this would be a very strange case to hit
		// 	return nil, nil, transports.ErrNotTransport
		// }
		buf, err := io.ReadAll(req.Body)
		if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) {
			// this would be a very strange case to hit
			return nil, nil, fmt.Errorf("%w: failed to buffer http body: %w", transports.ErrNotTransport, err)
		}
		return reg, transports.PrependToConn(c, bytes.NewBuffer(buf)), nil
	}
	return reg, c, nil
}
