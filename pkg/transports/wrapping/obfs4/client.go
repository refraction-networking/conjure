package obfs4

import (
	"context"
	"fmt"
	"io"
	"net"

	"github.com/refraction-networking/conjure/pkg/transports"
	pb "github.com/refraction-networking/conjure/proto"
	"github.com/refraction-networking/obfs4/transports/obfs4"

	pt "gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/goptlib"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

// ClientTransport implements the client side transport interface for the Min transport. The
// significant difference is that there is an instance of this structure per client session, where
// the station side Transport struct has one instance to be re-used for all sessions.
type ClientTransport struct {
	Parameters *pb.GenericTransportParams
	keys       Obfs4Keys
}

// Name returns a string identifier for the Transport for logging
func (*ClientTransport) Name() string {
	return "obfs4"
}

// String returns a string identifier for the Transport for logging (including string formatters)
func (*ClientTransport) String() string {
	return "obfs4"
}

// ID provides an identifier that will be sent to the conjure station during the registration so
// that the station knows what transport to expect connecting to the chosen phantom.
func (*ClientTransport) ID() pb.TransportType {
	return pb.TransportType_Obfs4
}

func (*ClientTransport) Prepare(ctx context.Context, dialer func(ctx context.Context, network, laddr, raddr string) (net.Conn, error)) error {
	return nil
}

// GetParams returns a generic protobuf with any parameters from both the registration and the
// transport.
func (t *ClientTransport) GetParams() (proto.Message, error) {
	return t.Parameters, nil
}

// SetParams allows the caller to set parameters associated with the transport, returning an
// error if the provided generic message is not compatible.
func (t *ClientTransport) SetParams(p any, unchecked ...bool) error {
	var parsedParams *pb.GenericTransportParams
	if params, ok := p.(*pb.GenericTransportParams); ok {
		// make a copy of params so that we don't modify the original during an active session.
		parsedParams = proto.Clone(params).(*pb.GenericTransportParams)
	} else if p == nil {
		parsedParams = &pb.GenericTransportParams{}
		parsedParams.RandomizeDstPort = proto.Bool(true)
	} else {
		return fmt.Errorf("unable to parse params")
	}
	t.Parameters = parsedParams
	return nil
}

// ParseParams gives the specific transport an option to parse a generic object into parameters
// provided by the station in the registration response during registration.
func (t ClientTransport) ParseParams(data *anypb.Any) (any, error) {
	if data == nil {
		return nil, nil
	}

	var m = &pb.GenericTransportParams{}
	err := transports.UnmarshalAnypbTo(data, m)
	return m, err
}

// GetDstPort returns the destination port that the client should open the phantom connection to
func (t *ClientTransport) GetDstPort(seed []byte, phantomSubnetSupportsRandPort bool) (uint16, error) {
	if t.Parameters == nil || !t.Parameters.GetRandomizeDstPort() || !phantomSubnetSupportsRandPort {
		return 443, nil
	}

	return transports.PortSelectorRange(portRangeMin, portRangeMax, seed)
}

// WrapConn creates the connection to the phantom address negotiated in the registration phase of
// Conjure connection establishment.
func (t ClientTransport) WrapConn(conn net.Conn) (net.Conn, error) {
	obfsTransport := obfs4.Transport{}
	args := pt.Args{}

	args.Add("node-id", t.keys.NodeID.Hex())
	args.Add("public-key", t.keys.PublicKey.Hex())
	args.Add("iat-mode", "1")

	c, err := obfsTransport.ClientFactory("")
	if err != nil {
		return nil, fmt.Errorf("failed to create client factory")
	}

	parsedArgs, err := c.ParseArgs(&args)
	if err != nil {
		return nil, fmt.Errorf("failed to parse obfs4 args")
	}

	d := func(network, address string) (net.Conn, error) {
		return conn, nil
	}

	return c.Dial("tcp", "", d, parsedArgs)
}

func (t *ClientTransport) PrepareKeys(pubkey [32]byte, sharedSecret []byte, dRand io.Reader) error {
	// Generate shared keys
	var err error
	t.keys, err = generateObfs4Keys(dRand)
	if err != nil {
		return err
	}
	return nil
}
