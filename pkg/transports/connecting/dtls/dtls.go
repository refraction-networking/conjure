package dtls

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/libp2p/go-reuseport"
	"github.com/refraction-networking/conjure/pkg/core"
	"github.com/refraction-networking/conjure/pkg/dtls"
	dd "github.com/refraction-networking/conjure/pkg/station/lib"
	"github.com/refraction-networking/conjure/pkg/transports"
	pb "github.com/refraction-networking/conjure/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

const listenPort = 41245

type Transport struct {
	dnat         *dnat
	dtlsListener *dtls.Listener
}

// Name returns name of the transport
func (Transport) Name() string {
	return "dtls"
}

// LogPrefix returns log prefix of the transport
func (Transport) LogPrefix() string {
	return "DTLS"
}

// GetIdentifier returns an identifier unique a registration
func (Transport) GetIdentifier(reg *dd.DecoyRegistration) string {
	return string(core.ConjureHMAC(reg.Keys.SharedSecret, "dtlsTrasportHMACString"))
}

// NewTransport creates a new dtls transport
func NewTransport() (*Transport, error) {
	addr := &net.UDPAddr{Port: listenPort}

	listener, err := dtls.Listen(addr)
	if err != nil {
		return nil, fmt.Errorf("error creating dtls listner: %v", err)
	}

	dnat, err := newDNAT()

	if err != nil {
		return nil, fmt.Errorf("error connecting to tun device for DNAT: %v", err)
	}

	return &Transport{
		dnat:         dnat,
		dtlsListener: listener,
	}, nil
}

// Connect takes a registraion and returns a dtls Conn connected to the client
func (t *Transport) Connect(ctx context.Context, reg *dd.DecoyRegistration) (net.Conn, error) {
	if reg.Transport != pb.TransportType_DTLS {
		return nil, transports.ErrNotTransport
	}

	clientAddr := net.UDPAddr{IP: net.ParseIP(reg.GetRegistrationAddress()), Port: int(reg.GetSrcPort())}

	err := t.dnat.addEntry(clientAddr.IP, uint16(clientAddr.Port), reg.PhantomIp, reg.PhantomPort)
	if err != nil {
		return nil, fmt.Errorf("error adding DNAT entry: %v", err)
	}

	laddr := net.UDPAddr{IP: net.ParseIP("0.0.0.0"), Port: listenPort}

	connCh := make(chan net.Conn, 2)
	errCh := make(chan error, 2)

	go func() {
		udpConn, err := reuseport.Dial("udp", laddr.String(), clientAddr.String())
		if err != nil {
			errCh <- fmt.Errorf("error connecting to dtls client: %v", err)
			return
		}

		dtlsConn, err := dtls.ClientWithContext(ctx, udpConn, &dtls.Config{PSK: reg.Keys.SharedSecret, SCTP: dtls.ServerAccept})
		if err != nil {
			errCh <- fmt.Errorf("error connecting to dtls client: %v", err)
			return
		}

		connCh <- dtlsConn
	}()

	go func() {
		conn, err := t.dtlsListener.AcceptWithContext(ctx, &dtls.Config{PSK: reg.Keys.SharedSecret, SCTP: dtls.ServerAccept})
		if err != nil {
			errCh <- fmt.Errorf("error accepting dtls connection from secret: %v", err)
			return
		}

		connCh <- conn
	}()

	var errs []error
	for i := 0; i < 2; i++ {
		select {
		case conn := <-connCh:
			if conn != nil {
				fmt.Printf("**********returning connj****************\n")

				return conn, nil // success, so return the connection
			}
		case err := <-errCh:
			if err != nil { // store the error
				errs = append(errs, err)
			}
		}
	}

	// combine errors into a single error
	var combinedErr error
	if len(errs) > 0 {
		errStrings := make([]string, len(errs))
		for i, err := range errs {
			errStrings[i] = err.Error()
		}
		combinedErr = fmt.Errorf(strings.Join(errStrings, "; "))
	}

	return nil, combinedErr // if we reached here, both attempts failed
}

func (Transport) GetSrcPort(libVersion uint, seed []byte, params any) (uint16, error) {
	parameters, ok := params.(*pb.DTLSTransportParams)
	if !ok {
		return 0, fmt.Errorf("bad parameters provided")
	}

	return uint16(parameters.GetSrcPort()), nil
}

func (Transport) GetDstPort(libVersion uint, seed []byte, params any) (uint16, error) {
	return transports.PortSelectorRange(portRangeMin, portRangeMax, seed)
}

func (Transport) GetProto() pb.IPProto {
	return pb.IPProto_Udp
}

func (Transport) ParseParams(libVersion uint, data *anypb.Any) (any, error) {
	var m = &pb.DTLSTransportParams{}
	err := transports.UnmarshalAnypbTo(data, m)
	return m, err
}

// ParamStrings returns an array of tag string that will be added to tunStats when a proxy
// session is closed. For now, no params of interest.
func (t Transport) ParamStrings(p any) []string {
	return nil
}
