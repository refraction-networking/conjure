package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	golog "log"
	"math/rand"
	"net"
	"os"
	"syscall"
	"time"

	cj "github.com/refraction-networking/conjure/application/lib"
	"github.com/refraction-networking/conjure/application/log"
	"github.com/refraction-networking/conjure/application/transports"
)

func acceptConnections(ctx context.Context, rm *cj.RegistrationManager, logger *log.Logger) {
	// listen for and handle incoming proxy traffic
	listenAddr := &net.TCPAddr{IP: nil, Port: 41245, Zone: ""}
	ln, err := net.ListenTCP("tcp", listenAddr)
	if err != nil {
		logger.Fatalf("failed to listen on %v: %v\n", listenAddr, err)
	}
	defer ln.Close()
	logger.Infof("[STARTUP] Listening on %v\n", ln.Addr())

	for {
		select {
		case <-ctx.Done():
			break
		default:
			newConn, err := ln.AcceptTCP()
			if err != nil {
				logger.Errorf("[ERROR] failed to AcceptTCP on %v: %v\n", ln.Addr(), err)
				continue
			}
			go handleNewConn(rm, newConn)
		}
	}
}

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
func handleNewConn(regManager *cj.RegistrationManager, clientConn *net.TCPConn) {
	defer clientConn.Close()
	logger := sharedLogger

	fd, err := clientConn.File()
	if err != nil {
		logger.Errorln("failed to get file descriptor on clientConn:", err)
		return
	}

	// TODO: if NOT mPort 443: just forward things and return
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

	var originalDst, originalSrc string
	if logClientIP {
		originalSrc = clientConn.RemoteAddr().String()
	} else {
		originalSrc = "_"
	}
	originalDst = originalDstIP.String()
	flowDescription := fmt.Sprintf("%s -> %s ", originalSrc, originalDst)
	logger = log.New(os.Stdout, "[CONN] "+flowDescription, golog.Ldate|golog.Lmicroseconds)

	count := regManager.CountRegistrations(originalDstIP)
	logger.Debugf("new connection (%d potential registrations)\n", count)
	cj.Stat().AddConn()

	// Pick random timeout between 10 and 60 seconds, down to millisecond precision
	ms := rand.Int63n(50000) + 10000
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

		// Copy into io.Discard to keep ACKing until the deadline.
		// This should help prevent fingerprinting; if we let the read
		// buffer fill up and stopped ACKing after 8192 + (buffer size)
		// bytes for obfs4, as an example, that would be quite clear.
		_, err = io.Copy(io.Discard, clientConn)
		if errors.Is(err, syscall.ECONNRESET) {
			// log reset error without client ip
			logger.Errorln("error occurred discarding data: rst")
		} else if et, ok := err.(net.Error); ok && et.Timeout() {
			logger.Errorln("error occurred discarding data: timeout")
		} else if err != nil {
			//Log any other error
			logger.Errorln("error occurred discarding data:", err)
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
			if errors.Is(err, syscall.ECONNRESET) {
				// log reset error without client ip
				logger.Errorln("error occurred discarding data: rst")
			} else if et, ok := err.(net.Error); ok && et.Timeout() {
				logger.Errorln("error occurred discarding data: timeout")
			} else if err != nil {
				//Log any other error
				logger.Errorln("error occurred discarding data:", err)
			}
			return
		}

		n, err := clientConn.Read(buf[:])
		if err != nil {
			if err, ok := err.(net.Error); ok && err.Timeout() {
				continue
			} else if errors.Is(err, syscall.ECONNRESET) {
				logger.Errorf("got error while reading from connection, giving up after %d bytes: rst\n", received.Len())
			} else if err != nil {
				logger.Errorf("got error while reading from connection, giving up after %d bytes: %v\n", received.Len(), err)
			}
			cj.Stat().ConnErr()
			return
		}
		received.Write(buf[:n])
		logger.Tracef("read %d bytes so far", received.Len())

	transports:
		for i, t := range possibleTransports {
			reg, wrapped, err = t.WrapConnection(&received, clientConn, originalDstIP, regManager)
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
				time.Sleep(d)
				return
			}

			// We found our transport! First order of business: disable deadline
			err = wrapped.SetDeadline(time.Time{})
			if err != nil {
				logger.Errorln("error occurred while setting deadline:", err)
			}

			logger.SetPrefix(fmt.Sprintf("[%s] %s ", t.LogPrefix(), reg.IDString()))
			logger.Debugf("registration found {reg_id: %s, phantom: %s, transport: %s}\n", reg.IDString(), originalDstIP, t.Name())

			regManager.MarkActive(reg)

			break readLoop
		}
	}

	cj.Proxy(reg, wrapped, logger)
	cj.Stat().CloseConn()
}
