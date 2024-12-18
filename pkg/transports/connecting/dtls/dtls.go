package dtls

import (
	"context"
	"fmt"
	"net"

	"github.com/libp2p/go-reuseport"
	"github.com/refraction-networking/conjure/pkg/core"
	"github.com/refraction-networking/conjure/pkg/core/interfaces"
	"github.com/refraction-networking/conjure/pkg/dtls"
	"github.com/refraction-networking/conjure/pkg/transports"
	pb "github.com/refraction-networking/conjure/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

const listenPort = 41245

type dtlsListener interface {
	AcceptWithContext(context.Context, *dtls.Config) (net.Conn, error)
}

type Transport struct {
	DNAT             interfaces.DNAT
	dtlsListener     dtlsListener
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
func NewTransport(logAuthFail, logOtherFail, logDialSuccess, logListenSuccess func(*net.IP), buildDnat interfaces.DnatBuilder) (*Transport, error) {
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

	params, ok := reg.TransportParams().(*pb.DTLSTransportParams)
	if !ok {
		return nil, fmt.Errorf("transport params is not *pb.DTLSTransportParams")
	}

	connCh := make(chan net.Conn)
	errCh := make(chan error)

	ctxCancel, cancel := context.WithCancel(ctx)
	defer cancel()

	go func() {

		is4 := reg.PhantomIP().To4() != nil

		clientAddr := &net.UDPAddr{}

		if is4 {
			clientAddr = &net.UDPAddr{IP: params.SrcAddr4.GetIP(), Port: int(params.SrcAddr4.GetPort())}
		} else {
			clientAddr = &net.UDPAddr{IP: params.SrcAddr6.GetIP(), Port: int(params.SrcAddr6.GetPort())}
		}

		err := t.DNAT.AddEntry(&clientAddr.IP, uint16(clientAddr.Port), reg.PhantomIP(), reg.GetDstPort())
		if err != nil {
			select {
			case errCh <- fmt.Errorf("error adding DNAT entry: %v", err):
			case <-ctxCancel.Done():
			}
			return
		}

		// reuseport checks for local address and distinguishes between v4 and v6
		laddr := &net.UDPAddr{}
		if is4 {
			laddr = &net.UDPAddr{IP: net.ParseIP("0.0.0.0"), Port: listenPort}
		} else {
			laddr = &net.UDPAddr{IP: net.ParseIP("[::]"), Port: listenPort}
		}

		udpConn, err := reuseport.Dial("udp", laddr.String(), clientAddr.String())
		if err != nil {
			select {
			case errCh <- fmt.Errorf("error connecting to dtls client: %v", err):
			case <-ctxCancel.Done():
			}
			return
		}

		dtlsConn, err := dtls.ClientWithContext(ctxCancel, udpConn, &dtls.Config{PSK: reg.SharedSecret(), SCTP: dtls.ServerAccept, Unordered: params.GetUnordered()})
		if err != nil {
			select {
			case errCh <- fmt.Errorf("error connecting to dtls client: %v", err):
			case <-ctxCancel.Done():
			}
			return
		}

		select {
		case connCh <- dtlsConn:
			t.logDialSuccess(&clientAddr.IP)
		case <-ctxCancel.Done():
			dtlsConn.Close()
		}
	}()

	go func() {
		conn, err := t.dtlsListener.AcceptWithContext(ctxCancel, &dtls.Config{PSK: reg.SharedSecret(), SCTP: dtls.ServerAccept, Unordered: params.GetUnordered()})
		if err != nil {
			select {
			case errCh <- fmt.Errorf("error accepting dtls connection from secret: %v", err):
			case <-ctxCancel.Done():
			}
			return
		}

		select {
		case connCh <- conn:
			logip := net.ParseIP(reg.GetRegistrationAddress())
			t.logListenSuccess(&logip)
		case <-ctxCancel.Done():
			conn.Close()
		}
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
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	// combine errors into a single error
	var combinedErr error
	for _, err := range errs {
		if combinedErr == nil {
			combinedErr = err
		} else {
			combinedErr = fmt.Errorf("%v, %v", combinedErr, err)
		}
	}

	return nil, combinedErr // if we reached here, both attempts failed
}

func (Transport) GetDstPort(libVersion uint, seed []byte, params any) (uint16, error) {
	if params == nil {
		return defaultPort, nil
	}

	dtlsParams, ok := params.(*pb.DTLSTransportParams)
	if !ok {
		return 0, fmt.Errorf("bad parameters provided")
	}

	if dtlsParams.GetRandomizeDstPort() {
		return transports.PortSelectorRange(portRangeMin, portRangeMax, seed)
	}

	return defaultPort, nil
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
