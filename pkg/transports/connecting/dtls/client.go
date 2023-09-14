package dtls

import (
	"context"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/refraction-networking/conjure/pkg/dtls"
	"github.com/refraction-networking/conjure/pkg/transports"
	pb "github.com/refraction-networking/conjure/proto"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

type dialFunc = func(ctx context.Context, network, laddr, raddr string) (net.Conn, error)

const (
	// port range boundaries for min when randomizing
	portRangeMin      = 1024
	portRangeMax      = 65535
	defaultPort       = 443
	defaultSTUNServer = "stun.voip.blackberry.com:3478"
)

// ClientTransport implements the client side transport interface for the DTLS transport. The
// significant difference is that there is an instance of this structure per client session, where
// the station side Transport struct has one instance to be re-used for all sessions.
type ClientTransport struct {
	// Parameters are fields that will be shared with the station in the registration
	Parameters *pb.DTLSTransportParams

	privPort            int
	pubPort             int
	psk                 []byte
	stunServer          string
	disableIRWorkaround bool
}

type ClientConfig struct {
	// STUNServer is the address of the stun server to use
	STUNServer string

	// DisableIRWorkaround disables sending an empty packet to workaround DTLS blocking in IR
	//
	// In Iran, blocking seems to happen by matching the first packet in a "flow" against DTLS packet format and blocking if it matches.
	// If the first packet is anything else packets are permitted. UDP dst port does not seem to change this.
	DisableIRWorkaround bool
}

// Name returns a string identifier for the Transport for logging
func (*ClientTransport) Name() string {
	return "dtls"
}

// String returns a string identifier for the Transport for logging (including string formatters)
func (*ClientTransport) String() string {
	return "dtls"
}

// ID provides an identifier that will be sent to the conjure station during the registration so
// that the station knows what transport to expect connecting to the chosen phantom.
func (*ClientTransport) ID() pb.TransportType {
	return pb.TransportType_DTLS
}

// GetParams returns a generic protobuf with any parameters from both the registration and the
// transport.
func (t *ClientTransport) GetParams() (proto.Message, error) {
	return t.Parameters, nil
}

// SetParams allows the caller to set parameters associated with the transport, returning an
// error if the provided generic message is not compatible.
func (t *ClientTransport) SetParams(p any, unchecked ...bool) error {
	switch params := p.(type) {
	case *pb.GenericTransportParams:
		if t.Parameters == nil {
			t.Parameters = &pb.DTLSTransportParams{}
		}

		t.Parameters.RandomizeDstPort = proto.Bool(params.GetRandomizeDstPort())
	case *ClientConfig:
		t.stunServer = params.STUNServer
		t.disableIRWorkaround = params.DisableIRWorkaround
	}

	return nil
}

// Prepare lets the transport use the dialer to prepare. This is called before GetParams to let the
// transport prepare stuff such as nat traversal.
func (t *ClientTransport) Prepare(ctx context.Context, dialer func(ctx context.Context, network, laddr, raddr string) (net.Conn, error)) error {
	if t.stunServer == "" {
		t.stunServer = defaultSTUNServer
	}

	privePort, pubPort, err := publicAddr(ctx, defaultSTUNServer, dialer)
	if err != nil {
		return fmt.Errorf("error finding public port: %v", err)
	}

	t.privPort = privePort
	t.pubPort = pubPort
	t.Parameters = &pb.DTLSTransportParams{SrcPort: proto.Uint32(uint32(pubPort))}

	return nil
}

func (*ClientTransport) DisableRegDelay() bool {
	return true
}

// GetDstPort returns the destination port that the client should open the phantom connection to
func (t *ClientTransport) GetDstPort(seed []byte) (uint16, error) {
	return transports.PortSelectorRange(portRangeMin, portRangeMax, seed)
}

func (t *ClientTransport) WrapDial(dialer dialFunc) (dialFunc, error) {
	dtlsDialer := func(ctx context.Context, network, localAddr, address string) (net.Conn, error) {
		// Create a context that will automatically cancel after 5 seconds or when the existing context is cancelled, whichever comes first.
		parentctx, parentcancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer parentcancel()
		ctxtimeout, cancel := context.WithTimeout(parentctx, 5*time.Second)
		defer cancel()

		conn, errListen := t.listen(ctxtimeout, dialer, address)
		if errListen != nil {
			// fallback to dial
			conn, errDial := t.dial(parentctx, dialer, address)
			if errDial != nil {
				return nil, fmt.Errorf("error listening: %v, error dialing: %v", errListen, errDial)
			}

			return conn, nil
		}

		return conn, nil
	}

	return dtlsDialer, nil
}

func (t *ClientTransport) listen(ctx context.Context, dialer dialFunc, address string) (net.Conn, error) {
	laddr := &net.UDPAddr{IP: net.ParseIP("0.0.0.0"), Port: t.privPort}

	if t.disableIRWorkaround {
		err := openUDPLimitTTL(ctx, laddr.String(), address, dialer)
		if err != nil {
			return nil, fmt.Errorf("error opening UDP port from gateway: %v", err)
		}
	} else {
		err := openUDP(ctx, laddr.String(), address, dialer)
		if err != nil {
			return nil, fmt.Errorf("error opening UDP port from gateway: %v", err)
		}
	}

	udpConn, err := dialer(ctx, "udp", laddr.String(), address)
	if err != nil {
		return nil, fmt.Errorf("error dialing udp: %v", err)
	}

	conn, err := dtls.ServerWithContext(ctx, udpConn, &dtls.Config{PSK: t.psk, SCTP: dtls.ClientOpen})
	if err != nil {
		return nil, fmt.Errorf("error listening for phantom: %v", err)
	}

	return conn, err
}

func (t *ClientTransport) dial(ctx context.Context, dialer dialFunc, address string) (net.Conn, error) {
	udpConn, err := dialer(ctx, "udp", "", address)
	if err != nil {
		return nil, fmt.Errorf("error dialing udp: %v", err)
	}

	conn, err := dtls.ClientWithContext(ctx, udpConn, &dtls.Config{PSK: t.psk, SCTP: dtls.ClientOpen})
	if err != nil {
		return nil, fmt.Errorf("error dialing as client: %v", err)
	}

	return conn, err
}

// PrepareKeys provides an opportunity for the transport to integrate the station public key
// as well as bytes from the deterministic random generator associated with the registration
// that this ClientTransport is attached t
func (t *ClientTransport) PrepareKeys(pubkey [32]byte, sharedSecret []byte, dRand io.Reader) error {
	t.psk = sharedSecret
	return nil
}

// ParseParams gives the specific transport an option to parse a generic object into parameters
// provided by the station in the registration response during registration.
func (ClientTransport) ParseParams(*anypb.Any) (any, error) {
	return nil, nil
}
