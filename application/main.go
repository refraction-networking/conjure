package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"syscall"
	"time"

	"github.com/golang/protobuf/proto"
	zmq "github.com/pebbe/zmq4"
	dd "github.com/refraction-networking/conjure/application/lib"
	pb "github.com/refraction-networking/gotapdance/protobuf"

	"github.com/refraction-networking/conjure/application/transports"
	"github.com/refraction-networking/conjure/application/transports/min"
	"github.com/refraction-networking/conjure/application/transports/obfs4"
)

func getOriginalDst(fd uintptr) (net.IP, error) {
	const SO_ORIGINAL_DST = 80
	if sockOpt, err := syscall.GetsockoptIPv6Mreq(int(fd), syscall.IPPROTO_IP, SO_ORIGINAL_DST); err == nil {
		// parse ipv4
		return net.IPv4(sockOpt.Multiaddr[4], sockOpt.Multiaddr[5], sockOpt.Multiaddr[6], sockOpt.Multiaddr[7]), nil
	} else if mtuinfo, err := syscall.GetsockoptIPv6MTUInfo(int(fd), syscall.IPPROTO_IPV6, SO_ORIGINAL_DST); err == nil {
		// parse ipv6
		return net.IP(mtuinfo.Addr.Addr[:]), nil
	} else {
		return nil, err
	}
}

// Handle connection from client
// NOTE: this is called as a goroutine
func handleNewConn(regManager *dd.RegistrationManager, clientConn *net.TCPConn) {
	const timeout = 30 * time.Second

	defer clientConn.Close()

	fd, err := clientConn.File()
	if err != nil {
		logger.Println("failed to get file descriptor on clientConn:", err)
		return
	}

	// TODO: if NOT mPort 443: just forward things and return
	fdPtr := fd.Fd()
	originalDstIP, err := getOriginalDst(fdPtr)
	if err != nil {
		logger.Println("failed to getOriginalDst from fd:", err)
		return
	}

	// We need to set the underlying file descriptor back into
	// non-blocking mode after calling Fd (which puts it into blocking
	// mode), or else deadlines won't work.
	err = syscall.SetNonblock(int(fdPtr), true)
	if err != nil {
		logger.Println("failed to set non-blocking mode on fd:", err)
	}
	fd.Close()

	originalDst := originalDstIP.String()
	originalSrc := clientConn.RemoteAddr().String()
	flowDescription := fmt.Sprintf("%s -> %s ", originalSrc, originalDst)
	logger := log.New(os.Stdout, "[CONN] "+flowDescription, log.Ldate|log.Lmicroseconds)

	count := regManager.CountRegistrations(originalDstIP)
	logger.Printf("new connection (%d potential registrations)\n", count)

	if count < 1 {
		// Here, reading from the connection would be pointless, but
		// since the kernel already ACK'd this connection, we gain no
		// benefit from instantly dropping the connection; the jig is
		// already up. We should sleep in line with other code paths
		// so the initiator of the connection gains no information
		// about the correctness of their connection.
		//
		// Possible TODO: use NFQUEUE to be able to drop the connection
		// in userspace before the SYN-ACK is sent, increasing probe
		// resistance.
		logger.Printf("no possible registrations, sleeping %v then dropping connection\n", timeout)
		time.Sleep(timeout)
		return
	}

	var buf [4096]byte
	received := bytes.Buffer{}
	possibleTransports := regManager.GetTransports()

	var reg *dd.DecoyRegistration
	var wrapped net.Conn

	// Give the client a timeout to send enough data to identify a transport.
	// This can be reset by transports to give more time for handshakes
	// after a transport is identified.
	deadline := time.Now().Add(timeout)
	clientConn.SetDeadline(deadline)

readLoop:
	for {
		if len(possibleTransports) < 1 {
			// Here, we delay until precisely the original deadline.
			// This means that the connection always dies at the timeout
			// even if we've determined that we shouldn't pick up the connection;
			// this should help resist against active probes.
			d := time.Until(deadline)
			logger.Printf("ran out of possible transports, sleeping %v then giving up\n", d)
			time.Sleep(d)
			return
		}

		n, err := clientConn.Read(buf[:])
		if err != nil {
			logger.Printf("got error while reading from connection, giving up: %v\n", err)
			return
		}
		received.Write(buf[:n])
		logger.Printf("read %d bytes so far", received.Len())

	transports:
		for i, t := range possibleTransports {
			reg, wrapped, err = t.WrapConnection(&received, clientConn, originalDstIP, regManager)
			if errors.Is(err, transports.ErrTryAgain) {
				continue transports
			} else if errors.Is(err, transports.ErrNotTransport) {
				logger.Printf("not transport %s, removing from checks\n", t.Name())
				delete(possibleTransports, i)
				continue transports
			} else if err != nil {
				// If we got here, the error might have been produced while attemtping
				// to wrap the connection, which means received and the connection
				// may no longer be valid. We should just give up on this connection.
				d := time.Until(deadline)
				logger.Printf("got unexpected error from transport %s, sleeping %v then giving up: %v\n", t.Name(), d, err)
				time.Sleep(d)
				return
			}

			// We found our transport! First order of business: disable deadline
			wrapped.SetDeadline(time.Time{})
			logger.SetPrefix(fmt.Sprintf("[%s] %s ", t.LogPrefix(), reg.IDString()))
			logger.Printf("registration found {reg_id: %s, phantom: %s, transport: %s, covert: %s}\n", reg.IDString(), originalDstIP, t.Name(), reg.Covert)
			break readLoop
		}
	}

	dd.Proxy(reg, wrapped, logger)
}

func get_zmq_updates(regManager *dd.RegistrationManager) {
	logger := log.New(os.Stdout, "[ZMQ] ", log.Ldate|log.Lmicroseconds)
	sub, err := zmq.NewSocket(zmq.SUB)
	if err != nil {
		logger.Printf("could not create new ZMQ socket: %v\n", err)
		return
	}
	defer sub.Close()

	connectAddr := "ipc://@zmq-proxy"
	sub.Connect(connectAddr)
	sub.SetSubscribe("")

	logger.Printf("ZMQ connected to %v\n", connectAddr)

	for {

		newRegs, err := recieve_zmq_message(sub, regManager)
		if err != nil || len(newRegs) == 0 {
			logger.Printf("Encountered err when creating Reg: %v\n", err)
			continue
		}

		go func() {
			// Handle multiple
			for _, reg := range newRegs {
				liveness, response := reg.PhantomIsLive()

				if liveness == false {
					regManager.AddRegistration(reg)
					logger.Printf("Adding registration %v: phantom response: %v\n", reg.IDString(), response)
				} else {
					logger.Printf("Dropping registration %v -- live phantom: %v\n", reg.IDString(), response)
				}
			}
		}()

	}
}

func recieve_zmq_message(sub *zmq.Socket, regManager *dd.RegistrationManager) ([]*dd.DecoyRegistration, error) {
	// var ipAddr []byte
	// var covertAddrLen, maskedAddrLen [1]byte

	var sharedSecret [32]byte
	var fixedSizePayload [6]byte
	var flags [1]byte
	minMsgLen := 32 + 6 + 1 // + 16

	msg, err := sub.RecvBytes(0)
	if err != nil {
		logger.Printf("error reading from ZMQ socket: %v\n", err)
		return nil, err
	}
	if len(msg) < minMsgLen {
		logger.Printf("short message of size %v\n", len(msg))
		return nil, fmt.Errorf("short message of size %v", len(msg))
	}

	msgReader := bytes.NewReader(msg)

	msgReader.Read(sharedSecret[:])
	msgReader.Read(fixedSizePayload[:])

	vspSize := binary.BigEndian.Uint16(fixedSizePayload[0:2]) - 16
	flags = [1]byte{fixedSizePayload[2]}

	clientToStationBytes := make([]byte, vspSize)

	msgReader.Read(clientToStationBytes)

	// parse c2s
	clientToStation := &pb.ClientToStation{}
	err = proto.Unmarshal(clientToStationBytes, clientToStation)
	if err != nil {
		logger.Printf("Failed to unmarshall ClientToStation: %v", err)
		return nil, err
	}

	conjureKeys, err := dd.GenSharedKeys(sharedSecret[:])

	// Register one or both of v4 and v6 based on support specified by the client
	var newRegs []*dd.DecoyRegistration

	if clientToStation.GetV4Support() {
		reg, err := regManager.NewRegistration(clientToStation, &conjureKeys, flags, false)
		if err != nil {
			logger.Printf("Failed to create registration: %v", err)
			return nil, err
		}

		// log phantom IP, shared secret, ipv6 support
		logger.Printf("New registration: %v\n", reg.String())

		newRegs = append(newRegs, reg)
	}

	if clientToStation.GetV6Support() {
		reg, err := regManager.NewRegistration(clientToStation, &conjureKeys, flags, true)
		if err != nil {
			logger.Printf("Failed to create registration: %v", err)
			return nil, err
		}

		// log phantom IP, shared secret, ipv6 support
		logger.Printf("New registration: %v\n", reg.String())
		newRegs = append(newRegs, reg)
	}

	return newRegs, nil
}

var logger *log.Logger

func main() {
	rand.Seed(time.Now().UnixNano())
	regManager := dd.NewRegistrationManager()
	logger = regManager.Logger

	regManager.AddTransport(pb.TransportType_MinTransport, min.Transport{})
	regManager.AddTransport(pb.TransportType_Obfs4Transport, obfs4.Transport{})

	go get_zmq_updates(regManager)

	go func() {
		for {
			time.Sleep(3 * time.Minute)
			regManager.RemoveOldRegistrations()
		}
	}()

	listenAddr := &net.TCPAddr{IP: nil, Port: 41245, Zone: ""}
	ln, err := net.ListenTCP("tcp", listenAddr)
	if err != nil {
		logger.Printf("failed to listen on %v: %v\n", listenAddr, err)
		return
	}
	defer ln.Close()
	logger.Printf("[STARTUP] Listening on %v\n", ln.Addr())

	for {
		newConn, err := ln.AcceptTCP()
		if err != nil {
			logger.Printf("[ERROR] failed to AcceptTCP on %v: %v\n", ln.Addr(), err)
			return // continue?
		}
		go handleNewConn(regManager, newConn)
	}
}
