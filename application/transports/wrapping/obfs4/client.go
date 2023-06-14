package obfs4

import (
	"fmt"
	"io"
	"net"

	pt "git.torproject.org/pluggable-transports/goptlib.git"
	dd "github.com/refraction-networking/conjure/application/lib"
	"github.com/refraction-networking/conjure/application/transports"
	"github.com/refraction-networking/conjure/pkg/core"
	pb "github.com/refraction-networking/gotapdance/protobuf"
	"gitlab.com/yawning/obfs4.git/transports/obfs4"

	"google.golang.org/protobuf/proto"
)

// ClientTransport implements the client side transport interface for the Min transport. The
// significant difference is that there is an instance of this structure per client session, where
// the station side Transport struct has one instance to be re-used for all sessions.
type ClientTransport struct {
	Parameters *pb.GenericTransportParams
	connectTag []byte
	keys       dd.ConjureSharedKeys
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

// GetParams returns a generic protobuf with any parameters from both the registration and the
// transport.
func (t *ClientTransport) GetParams() proto.Message {
	return t.Parameters
}

// SetParams allows the caller to set parameters associated with the transport, returning an
// error if the provided generic message is not compatible.
func (t *ClientTransport) SetParams(p any) error {
	params, ok := p.(*pb.GenericTransportParams)
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

// Connect creates the connection to the phantom address negotiated in the registration phase of
// Conjure connection establishment.
func (t ClientTransport) Connect(conn net.Conn) (net.Conn, error) {
	obfsTransport := obfs4.Transport{}
	args := pt.Args{}

	args.Add("node-id", t.keys.Obfs4Keys.NodeID.Hex())
	args.Add("public-key", t.keys.Obfs4Keys.PublicKey.Hex())
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

func (t *ClientTransport) Prepare(pubkey [32]byte, sharedSecret []byte, dRand io.Reader) error {
	t.connectTag = core.ConjureHMAC(sharedSecret, "obfs4TransportHMACString")
	// Generate shared keys
	var err error
	t.keys, err = dd.GenSharedKeys(sharedSecret, pb.TransportType_Obfs4)
	if err != nil {
		return fmt.Errorf("failed to generate shared keys")
	}
	return nil
}
