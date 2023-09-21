package connection

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	golog "log"
	"math/rand"
	"net"
	"os"
	"syscall"
	"time"

	"github.com/refraction-networking/conjure/pkg/core/interfaces"
	"github.com/refraction-networking/conjure/pkg/log"
	cj "github.com/refraction-networking/conjure/pkg/station/lib"
	"github.com/refraction-networking/conjure/pkg/transports"
	"github.com/refraction-networking/conjure/pkg/transports/connecting/dtls"
)

// ConnManagerConfig
type ConnManagerConfig struct {
	TraceDebugRate  int // rate at which to print Debug logging for connections. Rate is computed as 1/n - 0 indicates off.
	Logger          *log.Logger
	LogClientIP     bool
	NewConnDeadline time.Duration
}

type connManager struct {
	*connStats
	*ConnManagerConfig
	logger *log.Logger
}

type ConnHandler interface {
	interfaces.ConnectingTpStats
	interfaces.Stats
	BuildDTLSTransport(dtlsBuilder interfaces.DnatBuilder, logIPDTLS IPLogger) (*dtls.Transport, error)
}

// NewConnManager returns a connection handler for applying station side transport handling to
// incoming connections
func NewConnManager(conf *ConnManagerConfig) ConnHandler {
	return newConnManager(conf)
}
func newConnManager(conf *ConnManagerConfig) *connManager {
	if conf == nil {
		conf = &ConnManagerConfig{
			NewConnDeadline: 10 * time.Second,
			TraceDebugRate:  0,
		}
	}

	if conf.Logger == nil {
		conf.Logger = log.New(os.Stdout, "[CONN] ", golog.Ldate|golog.Lmicroseconds)
	}

	return &connManager{
		connStats:         &connStats{v4geoIPMap: make(map[uint]*asnCounts), v6geoIPMap: make(map[uint]*asnCounts)},
		ConnManagerConfig: conf,
		logger:            conf.Logger,
	}
}

// func (cm *connManager) acceptConnections(ctx context.Context, rm *cj.RegistrationManager, logger *log.Logger) {
// 	// listen for and handle incoming proxy traffic
// 	listenAddr := &net.TCPAddr{IP: nil, Port: 41245, Zone: ""}
// 	ln, err := net.ListenTCP("tcp", listenAddr)
// 	if err != nil {
// 		logger.Fatalf("failed to listen on %v: %v\n", listenAddr, err)
// 	}
// 	defer ln.Close()
// 	logger.Infof("[STARTUP] Listening on %v\n", ln.Addr())

// 	for {
// 		select {
// 		case <-ctx.Done():
// 			break
// 		default:
// 			newConn, err := ln.AcceptTCP()
// 			if err != nil {
// 				logger.Errorf("[ERROR] failed to AcceptTCP on %v: %v\n", ln.Addr(), err)
// 				continue
// 			}
// 			go cm.handleNewConn(rm, newConn)
// 		}
// 	}
// }

func getOriginalDst(fd uintptr) (net.IP, error) {
	const SockOptOriginalDst = 80
	if sockOpt, err := syscall.GetsockoptIPv6Mreq(int(fd), syscall.IPPROTO_IP, SockOptOriginalDst); err == nil {
		// parse ipv4
		return net.IPv4(sockOpt.Multiaddr[4], sockOpt.Multiaddr[5], sockOpt.Multiaddr[6], sockOpt.Multiaddr[7]), nil
	} else if mtuinfo, err := syscall.GetsockoptIPv6MTUInfo(int(fd), syscall.IPPROTO_IPV6, SockOptOriginalDst); err == nil {
		// parse ipv6
		return net.IP(mtuinfo.Addr.Addr[:]), nil
	} else {
		return nil, err
	}
}

// Handle connection from client
// NOTE: this is called as a goroutine
func (cm *connManager) handleNewConn(regManager *cj.RegistrationManager, clientConn *net.TCPConn) {
	defer clientConn.Close()
	logger := cm.logger

	fd, err := clientConn.File()
	if err != nil {
		logger.Errorln("failed to get file descriptor on clientConn:", err)
		return
	}

	fdPtr := fd.Fd()
	originalDstIP, err := getOriginalDst(fdPtr)
	if err != nil {
		logger.Errorln("failed to getOriginalDst from fd:", err)
		return
	}

	// We need to set the underlying file descriptor back into
	// non-blocking mode after calling Fd (which puts it into blocking
	// mode), or else deadlines won't work.
	err = syscall.SetNonblock(int(fdPtr), true)
	if err != nil {
		logger.Errorln("failed to set non-blocking mode on fd:", err)
	}
	fd.Close()

	cm.handleNewTCPConn(regManager, clientConn, originalDstIP)
}

func getRemoteAsIP(conn net.Conn) (remoteIP net.IP) {
	remoteAddr := conn.RemoteAddr()
	switch addr := remoteAddr.(type) {
	case *net.TCPAddr:
		remoteIP = addr.IP
	case *net.UDPAddr:
		remoteIP = addr.IP
	default:
		a := remoteAddr.String()
		// try parsing the returned address string as host:port
		host, _, err := net.SplitHostPort(a)
		if err != nil {
			// try parsing the returned address string as just an IP address
			remoteIP = net.ParseIP(a)
			break
		} else {
			// try parsing the returned host portion of the address as an IP address as opposed to a
			// domain name or other string.
			remoteIP = net.ParseIP(host)
		}
	}
	return
}

func (cm *connManager) handleNewTCPConn(regManager *cj.RegistrationManager, clientConn net.Conn, originalDstIP net.IP) {
	isIPv4 := originalDstIP.To4() != nil
	var originalDst, originalSrc string
	if cm.LogClientIP {
		originalSrc = clientConn.RemoteAddr().String()
	} else {
		originalSrc = "_"
	}
	originalDst = originalDstIP.String()
	flowDescription := fmt.Sprintf("%s -> %s ", originalSrc, originalDst)
	logger := log.New(os.Stdout, "[CONN] "+flowDescription, golog.Ldate|golog.Lmicroseconds)

	remoteIP := getRemoteAsIP(clientConn)
	if remoteIP == nil {
		// Socket returned non-IP Remote Address - we can't really use that. If testing w/ pipe try
		// wrapping with struct to provide mock RemoteAddr which return a real IP address.
		return
	}

	var asn uint = 0
	var cc string
	var err error
	cc, err = regManager.GeoIP.CC(remoteIP)
	if err != nil {
		logger.Errorln("Failed to get CC:", err)
		return
	}
	if cc != "unk" {
		// logger.Infoln("CC not unk:", cc, "ASN:", asn) // TESTING
		asn, err = regManager.GeoIP.ASN(remoteIP)
		if err != nil {
			logger.Errorln("Failed to get ASN:", err)
			return
		}
	}
	// logger.Infoln("CC:", cc, "ASN:", asn) // TESTING

	count := regManager.CountRegistrations(originalDstIP)
	logger.Debugf("new connection (%d potential registrations)\n", count)
	cj.Stat().AddConn()
	cm.addCreated(asn, cc, isIPv4)

	// Pick random timeout between 5 and 10 seconds, down to millisecond precision
	ms := rand.Int63n(5000) + 5000
	timeout := time.Duration(ms) * time.Millisecond

	// Give the client a deadline to send enough data to identify a transport.
	// This can be reset by transports to give more time for handshakes
	// after a transport is identified.
	deadline := time.Now().Add(timeout)
	err = clientConn.SetDeadline(deadline)
	if err != nil {
		logger.Errorln("error occurred while setting deadline:", err)
	}

	if count < 1 {
		// Here, reading from the connection would be pointless, but
		// since the kernel already ACK'd this connection, we gain no
		// benefit from instantly dropping the connection; the jig is
		// already up. We should keep reading in line with other code paths
		// so the initiator of the connection gains no information
		// about the correctness of their connection.
		//
		// Possible TODO: use NFQUEUE to be able to drop the connection
		// in userspace before the SYN-ACK is sent, increasing probe
		// resistance.
		logger.Debugf("no possible registrations, reading for %v then dropping connection\n", timeout)
		cj.Stat().AddMissedReg()
		cj.Stat().CloseConn()
		cm.createdToDiscard(asn, cc, isIPv4)

		// Copy into io.Discard to keep ACKing until the deadline.
		// This should help prevent fingerprinting; if we let the read
		// buffer fill up and stopped ACKing after 8192 + (buffer size)
		// bytes for obfs4, as an example, that would be quite clear.
		_, err = io.Copy(io.Discard, clientConn)
		err = generalizeErr(err)
		if errors.Is(err, errConnReset) {
			// log reset error without client ip
			logger.Errorln("error occurred discarding data (read 0 B): rst")
			cm.discardToReset(asn, cc, isIPv4)
		} else if errors.Is(err, errConnTimeout) {
			logger.Errorln("error occurred discarding data (read 0 B): timeout")
			cm.discardToTimeout(asn, cc, isIPv4)
		} else if errors.Is(err, errConnClosed) {
			cm.discardToClose(asn, cc, isIPv4)
		} else if err != nil {
			//Log any other error
			logger.Errorln("error occurred discarding data (read 0 B):", err)
			cm.discardToError(asn, cc, isIPv4)
		} else {
			cm.discardToClose(asn, cc, isIPv4)
		}
		return
	}

	var buf [4096]byte
	received := bytes.Buffer{}
	possibleTransports := regManager.GetWrappingTransports()

	var reg *cj.DecoyRegistration
	var wrapped net.Conn

readLoop:
	for {
		if len(possibleTransports) < 1 {
			logger.Warnf("ran out of possible transports, reading for %v then giving up\n", time.Until(deadline))
			cj.Stat().ConnErr()

			_, err = io.Copy(io.Discard, clientConn)
			err = generalizeErr(err)
			if errors.Is(err, errConnReset) {
				// log reset error without client ip
				logger.Errorf("error occurred discarding data (read %d B): rst\n", received.Len())
				cm.discardToReset(asn, cc, isIPv4)
			} else if errors.Is(err, errConnTimeout) {
				logger.Errorf("error occurred discarding data (read %d B): timeout\n", received.Len())
				cm.discardToTimeout(asn, cc, isIPv4)
			} else if errors.Is(err, errConnClosed) {
				cm.discardToClose(asn, cc, isIPv4)
			} else if err != nil {
				//Log any other error
				logger.Errorf("error occurred discarding data (read %d B): %v\n", received.Len(), err)
				cm.discardToError(asn, cc, isIPv4)
			} else {
				cm.discardToClose(asn, cc, isIPv4)
			}

			return
		}

		n, err := clientConn.Read(buf[:])
		err = generalizeErr(err)
		if err != nil {
			if errors.Is(err, errConnReset) {
				logger.Errorf("got error while reading from connection, giving up after %d bytes: rst\n", received.Len()+n)
				if received.Len() == 0 {
					cm.createdToReset(asn, cc, isIPv4)
				} else {
					cm.readToReset(asn, cc, isIPv4)
				}
			} else if errors.Is(err, errConnTimeout) {
				logger.Errorf("got error while reading from connection, giving up after %d bytes: timeout\n", received.Len()+n)
				if received.Len() == 0 {
					cm.createdToTimeout(asn, cc, isIPv4)
				} else {
					cm.readToTimeout(asn, cc, isIPv4)
				}
			} else if errors.Is(err, errConnClosed) {
				logger.Errorf("got error while reading from connection, giving up after %d bytes: closed\n", received.Len()+n)
				if received.Len() == 0 {
					cm.createdToClose(asn, cc, isIPv4)
				} else {
					cm.readToError(asn, cc, isIPv4)
				}
			} else {
				logger.Errorf("got error while reading from connection, giving up after %d bytes: %v\n", received.Len()+n, err)
				if received.Len() == 0 {
					cm.createdToError(asn, cc, isIPv4)
				} else {
					cm.readToError(asn, cc, isIPv4)
				}
			}
			cj.Stat().ConnErr()
			return
		}

		if received.Len() == 0 {
			cm.createdToCheck(asn, cc, isIPv4)
		} else {
			cm.readToCheck(asn, cc, isIPv4)
		}

		received.Write(buf[:n])
		logger.Tracef("read %d bytes so far", received.Len())

	transports:
		for i, t := range possibleTransports {
			wrappedReg, wrappedConn, err := t.WrapConnection(&received, clientConn, originalDstIP, regManager)

			err = generalizeErr(err)
			if errors.Is(err, transports.ErrTryAgain) {
				continue transports
			} else if errors.Is(err, transports.ErrNotTransport) {
				logger.Tracef("not transport %s, removing from checks\n", t.Name())
				delete(possibleTransports, i)
				continue transports
			} else if err != nil {
				// If we got here, the error might have been produced while attempting
				// to wrap the connection, which means received and the connection
				// may no longer be valid. We should just give up on this connection.
				d := time.Until(deadline)
				logger.Warnf("got unexpected error from transport %s, sleeping %v then giving up: %v\n", t.Name(), d, err)
				cj.Stat().ConnErr()
				cm.checkToError(asn, cc, isIPv4)
				time.Sleep(d)
				return
			}

			ok := false
			reg, ok = wrappedReg.(*cj.DecoyRegistration)
			if !ok {
				logger.Errorf("unexpected returned reg type from transport: %T, expected: %T", wrapped, reg)
				delete(possibleTransports, i)
				continue transports
			}
			// set outer wrapped var
			wrapped = wrappedConn

			// We found our transport! First order of business: disable deadline
			err = wrapped.SetDeadline(time.Time{})
			if err != nil {
				logger.Errorln("error occurred while setting deadline:", err)
			}

			logger.SetPrefix(fmt.Sprintf("[%s] %s ", t.LogPrefix(), reg.IDString()))
			logger.Debugf("registration found {reg_id: %s, phantom: %s, transport: %s}\n", reg.IDString(), originalDstIP, t.Name())

			regManager.MarkActive(reg)

			cm.checkToFound(asn, cc, isIPv4)
			break readLoop
		}

		if len(possibleTransports) < 1 {
			cm.checkToDiscard(asn, cc, isIPv4)
		} else if received.Len() == 0 {
			cm.checkToCreated(asn, cc, isIPv4)
		} else {
			cm.checkToRead(asn, cc, isIPv4)
		}
	}

	cj.Proxy(reg, wrapped, logger)
	cj.Stat().CloseConn()
}

var (
	// errConnReset replaces the reset error in the halfpipe to remove ips and extra bytes
	errConnReset = errors.New("rst")

	// errConnTimeout replaces the ip.timeout error in the halfpipe to remove ips and extra bytes
	errConnTimeout = errors.New("timeout")

	// replaces refused error to prevent client IP logging
	errConnRefused = errors.New("refused")

	// errUnreachable replaces unreachable error to prevent client IP logging
	errUnreachable = errors.New("unreachable")

	// errConnAborted replaces aborted error to prevent client IP logging
	errConnAborted = errors.New("aborted")

	// errConnClosed replaces closed errors to prevent client IP logging
	errConnClosed = errors.New("closed")
)

func generalizeErr(err error) error {
	switch {
	case err == nil:
		return nil
	case
		errors.Is(err, net.ErrClosed), // Errors indicating operation on something already closed.
		errors.Is(err, io.EOF),
		errors.Is(err, syscall.EPIPE),
		errors.Is(err, os.ErrClosed):
		return errConnClosed
	case errors.Is(err, syscall.ECONNRESET):
		return errConnReset
	case errors.Is(err, syscall.ECONNREFUSED):
		return errConnRefused
	case errors.Is(err, syscall.ECONNABORTED):
		return errConnAborted
	case errors.Is(err, syscall.EHOSTUNREACH):
		return errUnreachable
	default:
		if errN, ok := err.(net.Error); ok && errN.Timeout() {
			return errConnTimeout
		}
	}

	// if it is not a well known error, return it
	return err
}
