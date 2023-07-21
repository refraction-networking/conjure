package utls

import (
	"crypto/rand"
	"fmt"
	"io"
	"net"

	"github.com/refraction-networking/conjure/pkg/core"
	"github.com/refraction-networking/conjure/pkg/transports"
	pb "github.com/refraction-networking/conjure/proto"
	tls "github.com/refraction-networking/utls"
	"google.golang.org/protobuf/proto"
)

// ClientTransport implements the client side transport interface for the Min transport. The
// significant difference is that there is an instance of this structure per client session, where
// the station side Transport struct has one instance to be re-used for all sessions.
//
// External libraries must set parameters through SetParams using uTLSTransportParams.
type ClientTransport struct {
	// Parameters are fields that will be shared with the station in the registration
	Parameters *pb.UTLSTransportParams

	// // state tracks fields internal to the registrar that survive for the lifetime
	// // of the transport session without being shared - i.e. local derived keys.
	// state any
	TagObfuscator transports.Obfuscator

	hmacID           []byte
	stationPublicKey [32]byte
	rand             io.Reader
}

// Name returns a string identifier for the Transport for logging
func (*ClientTransport) Name() string {
	return "min"
}

// String returns a string identifier for the Transport for logging (including string formatters)
func (*ClientTransport) String() string {
	return "min"
}

// ID provides an identifier that will be sent to the conjure station during the registration so
// that the station knows what transport to expect connecting to the chosen phantom.
func (*ClientTransport) ID() pb.TransportType {
	return pb.TransportType_Min
}

// GetParams returns a generic protobuf with any parameters from both the registration and the
// transport.
func (t *ClientTransport) GetParams() proto.Message {
	return t.Parameters
}

// SetParams allows the caller to set parameters associated with the transport, returning an
// error if the provided generic message is not compatible.
func (t *ClientTransport) SetParams(p any) error {
	params, ok := p.(*pb.UTLSTransportParams)
	if !ok {
		return fmt.Errorf("unable to parse params")
	}
	t.Parameters = params

	return nil
}

// GetDstPort returns the destination port that the client should open the phantom connection to
func (t *ClientTransport) GetDstPort(seed []byte, params any) (uint16, error) {
	if t.Parameters == nil || !t.Parameters.GetRandomizeDstPort() {
		return defaultPort, nil
	}

	return transports.PortSelectorRange(portRangeMin, portRangeMax, seed)
}

// PrepareKeys provides an opportunity for the transport to integrate the station public key
// as well as bytes from the deterministic random generator associated with the registration
// that this ClientTransport is attached to.
func (t *ClientTransport) PrepareKeys(pubkey [32]byte, sharedSecret []byte, dRand io.Reader) error {
	t.hmacID = core.ConjureHMAC(sharedSecret, "PrefixTransportHMACString")
	t.stationPublicKey = pubkey
	t.rand = dRand
	return nil
}

// WrapConn returns a net.Conn connection given a context and ConjureReg
func (t *ClientTransport) WrapConn(conn net.Conn) (net.Conn, error) {

	randVal := [32]byte{}
	n, err := rand.Read(randVal[:])
	if err != nil {
		return nil, err
	} else if n != 32 {
		return nil, fmt.Errorf("ecpected 32 bytes of randmom, received %d", n)
	}

	if t.Parameters == nil {
		return nil, fmt.Errorf("missinf parameters")
	}

	cert, err := newCertificate(randVal[:])
	serverConfig := &tls.Config{
		Certificates:           []tls.Certificate{*cert},
		MinVersion:             tls.VersionTLS10,
		MaxVersion:             tls.VersionTLS12,
		SessionTicketsDisabled: false,
		ClientAuth:             tls.RequireAnyClientCert,
		VerifyConnection:       buildSymmetricVerifier(randVal[:]),
		CipherSuites:           []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
	}

	serverSession, err := tls.ForgeServerSessionState(randVal[:], serverConfig, tls.HelloChrome_Auto)

	sessionTicket, err := serverSession.MakeEncryptedTicket(randVal, &tls.Config{})

	// Create a session ticket that wasn't actually issued by the server.
	sessionState := tls.MakeClientSessionState(sessionTicket, uint16(tls.VersionTLS12),
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		randVal[:],
		nil, nil)

	config := &tls.Config{
		ServerName:   string(t.Parameters.Sni),
		Certificates: []tls.Certificate{*cert},
		// VerifyConnection: buildSymmetricVerifier(randVal[:]),
	}
	clientTLSConn := tls.UClient(conn, config, tls.HelloGolang)
	if err != nil {
		return nil, err
	}

	//[ ] TODO: set the random as sessionID and CH readnom

	err = clientTLSConn.BuildHandshakeState()
	if err != nil {
		return nil, err
	}
	// SetSessionState sets the session ticket, which may be preshared or fake.
	err = clientTLSConn.SetSessionState(sessionState)
	if err != nil {
		return nil, err
	}
	return clientTLSConn, nil
}
