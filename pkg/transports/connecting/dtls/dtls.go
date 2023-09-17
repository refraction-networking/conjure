package dtls

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/libp2p/go-reuseport"
	"github.com/refraction-networking/conjure/pkg/core"
	"github.com/refraction-networking/conjure/pkg/core/interfaces"
	"github.com/refraction-networking/conjure/pkg/dtls"
	"github.com/refraction-networking/conjure/pkg/transports"
	pb "github.com/refraction-networking/conjure/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

const listenPort = 41245

type Transport struct {
	DNAT             interfaces.DNAT
	dtlsListener     *dtls.Listener
	logDialSuccess   func(*net.IP)
	logListenSuccess func(*net.IP)
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
func (Transport) GetIdentifier(reg transports.Registration) string {
	return string(core.ConjureHMAC(reg.SharedSecret(), "dtlsTrasportHMACString"))
}

// NewTransport creates a new dtls transport
func NewTransport(logAuthFail func(*net.IP), logOtherFail func(*net.IP), logDialSuccess func(*net.IP), logListenSuccess func(*net.IP), buildDnat interfaces.DnatBuilder) (*Transport, error) {
	addr := &net.UDPAddr{Port: listenPort}

	listener, err := dtls.Listen("udp", addr, &dtls.Config{LogAuthFail: logAuthFail, LogOther: logAuthFail})
	if err != nil {
		return nil, fmt.Errorf("error creating dtls listner: %v", err)
	}

	dnat, err := buildDnat()

	if err != nil {
		return nil, fmt.Errorf("error connecting to tun device for DNAT: %v", err)
	}

	return &Transport{
		DNAT:             dnat,
		dtlsListener:     listener,
		logDialSuccess:   logDialSuccess,
		logListenSuccess: logListenSuccess,
	}, nil
}

// Connect takes a registraion and returns a dtls Conn connected to the client
func (t *Transport) Connect(ctx context.Context, reg transports.Registration) (net.Conn, error) {
	if reg.TransportType() != pb.TransportType_DTLS {
		return nil, transports.ErrNotTransport
	}

	clientAddr := net.UDPAddr{IP: net.ParseIP(reg.GetRegistrationAddress()), Port: int(reg.GetSrcPort())}

	err := t.DNAT.AddEntry(&clientAddr.IP, uint16(clientAddr.Port), reg.PhantomIP(), reg.GetDstPort())
	if err != nil {
		fmt.Printf("error adding DNAT entry: %v\n", err)
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

		dtlsConn, err := dtls.ClientWithContext(ctx, udpConn, &dtls.Config{PSK: reg.SharedSecret(), SCTP: dtls.ServerAccept})
		if err != nil {
			errCh <- fmt.Errorf("error connecting to dtls client: %v", err)
			return
		}
		t.logDialSuccess(&clientAddr.IP)

		connCh <- dtlsConn
	}()

	go func() {
		conn, err := t.dtlsListener.AcceptWithContext(ctx, &dtls.Config{PSK: reg.SharedSecret(), SCTP: dtls.ServerAccept})
		if err != nil {
			errCh <- fmt.Errorf("error accepting dtls connection from secret: %v", err)
			return
		}
		logip := net.ParseIP(reg.GetRegistrationAddress())
		t.logListenSuccess(&logip)

		connCh <- conn
	}()

	var errs []error
	for i := 0; i < 2; i++ {
		select {
		case conn := <-connCh:
			if conn != nil {
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
