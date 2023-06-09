package obfs4

import (
	"fmt"
	"io"

	"github.com/refraction-networking/conjure/application/transports"
	pb "github.com/refraction-networking/gotapdance/protobuf"
	"gitlab.com/yawning/obfs4.git/common/ntor"
	"golang.org/x/crypto/curve25519"

	"google.golang.org/protobuf/proto"
)

// ClientTransport implements the client side transport interface for the Min transport. The
// significant difference is that there is an instance of this structure per client session, where
// the station side Transport struct has one instance to be re-used for all sessions.
type ClientTransport struct {
	Parameters *pb.GenericTransportParams

	keys obfs4Keys
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

// // Connect creates the connection to the phantom address negotiated in the registration phase of
// // Conjure connection establishment.
// func (*ClientTransport) Connect(ctx context.Context, reg *cj.ConjureReg) (net.Conn, error) {
// 	return nil, nil
// }

// Prepare provides an opportunity for the transport to integrate the station public key
// as well as bytes from the deterministic random generator associated with the registration
// that this ClientTransport is attached to.
func (t *ClientTransport) Prepare(pubkey [32]byte, sharedSecret []byte, dRand io.Reader) error {
	var err error
	t.keys, err = generateObfs4Keys(dRand)
	return err
}

type obfs4Keys struct {
	PrivateKey *ntor.PrivateKey
	PublicKey  *ntor.PublicKey
	NodeID     *ntor.NodeID
}

func generateObfs4Keys(rand io.Reader) (obfs4Keys, error) {
	keys := obfs4Keys{
		PrivateKey: new(ntor.PrivateKey),
		PublicKey:  new(ntor.PublicKey),
		NodeID:     new(ntor.NodeID),
	}

	_, err := rand.Read(keys.PrivateKey[:])
	if err != nil {
		return keys, err
	}

	keys.PrivateKey[0] &= 248
	keys.PrivateKey[31] &= 127
	keys.PrivateKey[31] |= 64

	pub, err := curve25519.X25519(keys.PrivateKey[:], curve25519.Basepoint)
	if err != nil {
		return keys, err
	}
	copy(keys.PublicKey[:], pub)

	_, err = rand.Read(keys.NodeID[:])
	return keys, err
}
