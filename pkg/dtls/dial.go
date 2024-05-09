package dtls

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"time"

	"github.com/pion/dtls/v2"
	"github.com/pion/dtls/v2/pkg/protocol/handshake"
)

// Dial creates a DTLS connection to the given network address using the given shared secret
func Dial(remoteAddr *net.UDPAddr, config *Config) (net.Conn, error) {
	return DialWithContext(context.Background(), remoteAddr, config)
}

// DialWithContext like Dial, but includes context for cancellation and timeouts.
func DialWithContext(ctx context.Context, remoteAddr *net.UDPAddr, config *Config) (net.Conn, error) {
	conn, err := net.DialUDP("udp", nil, remoteAddr)
	if err != nil {
		return nil, err
	}

	return ClientWithContext(ctx, conn, config)
}

// Client establishes a DTLS connection using an existing connection and a seed.
func Client(conn net.Conn, config *Config) (net.Conn, error) {
	return ClientWithContext(context.Background(), conn, config)
}

// DialWithContext creates a DTLS connection to the given network address using the given shared secret
func ClientWithContext(ctx context.Context, conn net.Conn, config *Config) (net.Conn, error) {

	dtlsConn, err := dtlsCtx(ctx, conn, config)
	if err != nil {
		return nil, fmt.Errorf("error creating dtls connection: %w", err)
	}

	ddl, ok := ctx.Deadline()
	if ok {
		err := conn.SetDeadline(ddl)
		if err != nil {
			return nil, fmt.Errorf("error setting deadline: %v", err)
		}
	}

	wrappedConn, err := wrapSCTP(dtlsConn, config)
	if err != nil {
		dtlsConn.Close()
		return nil, err
	}

	err = conn.SetDeadline(time.Time{})
	if err != nil {
		return nil, fmt.Errorf("error setting deadline: %v", err)
	}

	err = wrappedConn.SetDeadline(time.Time{})
	if err != nil {
		return nil, fmt.Errorf("error setting deadline: %v", err)
	}

	return wrappedConn, nil
}

func dtlsCtx(ctx context.Context, conn net.Conn, config *Config) (net.Conn, error) {
	clientCert, serverCert, err := certsFromSeed(config.PSK)

	if err != nil {
		return nil, fmt.Errorf("error generating certs: %v", err)
	}

	clientHelloRandom, err := clientHelloRandomFromSeed(config.PSK)
	if err != nil {
		return nil, fmt.Errorf("error generating client hello random: %v", err)
	}

	verifyServerCertificate := func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
		if len(rawCerts) != 1 {
			return fmt.Errorf("expected 1 peer certificate, got %v", len(rawCerts))
		}

		err := verifyCert(rawCerts[0], serverCert.Certificate[0])
		if err != nil {
			return fmt.Errorf("error verifying server certificate: %v", err)
		}

		return nil
	}

	// Prepare the configuration of the DTLS connection
	dtlsConf := &dtls.Config{
		Certificates:            []tls.Certificate{*clientCert},
		ExtendedMasterSecret:    dtls.RequireExtendedMasterSecret,
		CustomClientHelloRandom: func() [handshake.RandomBytesLength]byte { return clientHelloRandom },

		// We use VerifyPeerCertificate to authenticate the peer's certificate. This is necessary as Go's non-deterministic ECDSA signatures and hash comparison method for self-signed certificates can cause verification failure.
		InsecureSkipVerify:    true,
		VerifyPeerCertificate: verifyServerCertificate,
	}

	return dtls.ClientWithContext(ctx, conn, dtlsConf)

}
