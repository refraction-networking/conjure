// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package dtls

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/pion/dtls/v2"
	"github.com/pion/dtls/v2/pkg/protocol/handshake"
	"github.com/pion/transport/v2/udp"
)

const defaultAcceptTimeout = 5 * time.Second

// Listen creates a listener and starts listening
func Listen(network string, laddr *net.UDPAddr, config *Config) (*Listener, error) {
	lc := udp.ListenConfig{}
	parent, err := lc.Listen(network, laddr)
	if err != nil {
		return nil, err
	}

	return NewListener(parent, config)
}

func (l *Listener) acceptLoop() {
	// Prepare the configuration of the DTLS connection
	config := &dtls.Config{
		ExtendedMasterSecret:    dtls.RequireExtendedMasterSecret,
		ClientAuth:              dtls.RequireAnyClientCert,
		GetCertificate:          l.getCertificateFromClientHello,
		VerifyConnection:        l.verifyConnection,
		InsecureSkipVerifyHello: true,
	}

	for {
		select {
		case <-l.closed:
			return
		default:
			c, err := l.parent.Accept()
			if err != nil {
				continue
			}

			go func() {
				ctx, cancel := context.WithTimeout(context.Background(), defaultAcceptTimeout)
				defer cancel()
				newDTLSConn, err := dtls.ServerWithContext(ctx, c, config)
				if err != nil {
					switch addr := c.RemoteAddr().(type) {
					case *net.UDPAddr:
						l.logIP(err, &addr.IP)
					case *net.TCPAddr:
						l.logIP(err, &addr.IP)
					case *net.IPAddr:
						l.logIP(err, &addr.IP)
					}

					return
				}

				connState := newDTLSConn.ConnectionState()
				connID := connState.RemoteRandomBytes()

				acceptCh, err := l.chFromID(connID)

				if err != nil {
					return
				}

				select {
				case acceptCh <- newDTLSConn:
					return
				case <-ctx.Done():
					return
				}
			}()
		}
	}
}

func (l *Listener) logIP(err error, ip *net.IP) {
	var terr *dtls.TemporaryError
	if errors.As(err, &terr) {
		l.logOther(ip)
	}
	l.logAuthFail(ip)
}

// NewListener creates a DTLS listener which accepts connections from an inner Listener.
func NewListener(inner net.Listener, config *Config) (*Listener, error) {
	// the default cert is only used for checking avaliable cipher suites
	defaultCert, err := randomCertificate()
	if err != nil {
		return nil, fmt.Errorf("error generating default random cert: %v", err)
	}

	newDTLSListner := Listener{
		parent:      inner,
		connMap:     map[[handshake.RandomBytesLength]byte](chan net.Conn){},
		connToCert:  map[[handshake.RandomBytesLength]byte]*certPair{},
		defaultCert: defaultCert,
		closed:      make(chan struct{}),
		logAuthFail: config.LogAuthFail,
		logOther:    config.LogOther,
	}

	go newDTLSListner.acceptLoop()

	return &newDTLSListner, nil
}

// Listener represents a DTLS Listener
type Listener struct {
	parent          net.Listener
	connMap         map[[handshake.RandomBytesLength]byte](chan net.Conn)
	connMapMutex    sync.Mutex
	connToCert      map[[handshake.RandomBytesLength]byte]*certPair
	connToCertMutex sync.Mutex
	defaultCert     *tls.Certificate
	logAuthFail     func(*net.IP)
	logOther        func(*net.IP)

	closeOnce sync.Once
	closed    chan struct{}
}

// Close closes the listener.
// Any blocked Accept operations will be unblocked and return errors.
// Already Accepted connections are not closed.
func (l *Listener) Close() error {
	l.closeOnce.Do(func() { close(l.closed) })
	return l.parent.Close()
}

// Addr returns the listener's network address.
func (l *Listener) Addr() net.Addr {
	return l.parent.Addr()
}

func (l *Listener) verifyConnection(state *dtls.State) error {

	certs, err := l.getCert(state.RemoteRandomBytes())
	if err != nil {
		return err
	}

	if len(state.PeerCertificates) != 1 {
		return fmt.Errorf("expected 1 peer certificate, got %v", len(state.PeerCertificates))
	}

	err = verifyCert(state.PeerCertificates[0], certs.clientCert.Certificate[0])
	if err != nil {
		return fmt.Errorf("error verifying peer certificate: %v", err)
	}

	return nil
}

func (l *Listener) getCert(id [handshake.RandomBytesLength]byte) (*certPair, error) {
	l.connToCertMutex.Lock()
	defer l.connToCertMutex.Unlock()

	certs, ok := l.connToCert[id]
	if !ok {
		return nil, fmt.Errorf("no matching certificate found with client hello random")
	}

	return certs, nil

}

// Accept accepts a connection with shared secret
func (l *Listener) Accept(config *Config) (net.Conn, error) {
	// Call the new function with a background context
	return l.AcceptWithContext(context.Background(), config)
}

// AcceptWithContext accepts a connection with shared secret, with a context
func (l *Listener) AcceptWithContext(ctx context.Context, config *Config) (net.Conn, error) {

	conn, err := l.acceptDTLSConn(ctx, config)
	if err != nil {
		return nil, err
	}

	ddl, ok := ctx.Deadline()
	if ok {
		err := conn.SetDeadline(ddl)
		if err != nil {
			return nil, fmt.Errorf("error setting deadline: %v", err)
		}
	}
	wrappedConn, err := wrapSCTP(conn, config)
	if err != nil {
		conn.Close()
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

func (l *Listener) acceptDTLSConn(ctx context.Context, config *Config) (net.Conn, error) {
	clientCert, serverCert, err := certsFromSeed(config.PSK)
	if err != nil {
		return &dtls.Conn{}, fmt.Errorf("error generating certificatess from seed: %v", err)
	}

	connID, err := clientHelloRandomFromSeed(config.PSK)
	if err != nil {
		return &dtls.Conn{}, err
	}

	err = l.registerCert(connID, clientCert, serverCert)
	if err != nil {
		return nil, fmt.Errorf("error registering cert: %v", err)
	}
	defer l.removeCert(connID)

	connCh, err := l.registerChannel(connID)
	if err != nil {
		return nil, fmt.Errorf("error registering channel: %v", err)
	}
	defer l.removeChannel(connID)

	select {
	case conn := <-connCh:
		return conn, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (l *Listener) registerCert(connID [handshake.RandomBytesLength]byte, clientCert, serverCert *tls.Certificate) error {
	l.connToCertMutex.Lock()
	defer l.connToCertMutex.Unlock()

	if l.connToCert[connID] != nil {
		return fmt.Errorf("seed already registered")
	}

	l.connToCert[connID] = &certPair{clientCert: clientCert, serverCert: serverCert}
	return nil
}

func (l *Listener) removeCert(connID [handshake.RandomBytesLength]byte) {
	l.connToCertMutex.Lock()
	defer l.connToCertMutex.Unlock()
	delete(l.connToCert, connID)
}

func (l *Listener) registerChannel(connID [handshake.RandomBytesLength]byte) (<-chan net.Conn, error) {
	l.connMapMutex.Lock()
	defer l.connMapMutex.Unlock()

	if l.connMap[connID] != nil {
		return nil, fmt.Errorf("seed already registered")
	}

	connChan := make(chan net.Conn, 1)
	l.connMap[connID] = connChan

	return connChan, nil
}

func (l *Listener) chFromID(id [handshake.RandomBytesLength]byte) (chan<- net.Conn, error) {

	l.connMapMutex.Lock()
	defer l.connMapMutex.Unlock()

	acceptCh, ok := l.connMap[id]

	if !ok {
		return nil, fmt.Errorf("id not registered")
	}

	return acceptCh, nil
}

func (l *Listener) removeChannel(connID [handshake.RandomBytesLength]byte) {
	l.connMapMutex.Lock()
	defer l.connMapMutex.Unlock()

	delete(l.connMap, connID)
}

func (l *Listener) getCertificateFromClientHello(clientHello *dtls.ClientHelloInfo) (*tls.Certificate, error) {
	// This function is sometimes called by the dtls library to get the availiable ciphersuites,
	// respond with a default certificate with the availible ciphersuites
	if clientHello.CipherSuites == nil {
		return l.defaultCert, nil
	}

	l.connToCertMutex.Lock()
	defer l.connToCertMutex.Unlock()

	certs, ok := l.connToCert[clientHello.RandomBytes]

	if !ok {
		// Respond with random server certificate if not registered, will reject client cert later during handshake
		randomCert, err := randomCertificate()
		if err != nil {
			return nil, fmt.Errorf("failed to generate random certificate: %v", err)
		}

		return randomCert, nil
	}

	return certs.serverCert, nil
}

func randomCertificate() (*tls.Certificate, error) {
	return newCertificate(rand.Reader)
}
