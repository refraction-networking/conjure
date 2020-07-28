package main

import (
	"log"
	"net"
	"os"
	"syscall"
	"time"

	"github.com/golang/protobuf/proto"
	zmq "github.com/pebbe/zmq4"
	dd "github.com/refraction-networking/conjure/application/lib"
	pb "github.com/refraction-networking/gotapdance/protobuf"
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
	defer clientConn.Close()

	fd, err := clientConn.File()
	if err != nil {
		logger.Printf("failed to get file descriptor on clientConn: %v\n", err)
		return
	}

	// TODO: if NOT mPort 443: just forward things and return

	originalDstIP, err := getOriginalDst(fd.Fd())
	if err != nil {
		logger.Println("failed to getOriginalDst from fd:", err)
		return
	}

	dd.MinTransportProxy(regManager, clientConn, originalDstIP)

	/*
		proxyHandler := dd.ProxyFactory(reg, 0)
		if proxyHandler != nil {
			logger.Printf("New Connection: source: %s, phantom: %s, shared secret: %s\n",
				clientConn.RemoteAddr().String(), reg.DarkDecoy.String(), reg.IDString())
			proxyHandler(reg, clientConn, originalDstIP)
		} else {
			logger.Printf("failed to initialize proxy, unknown or unimplemented protocol.\n")
			return
		}*/
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
	msg, err := sub.RecvBytes(0)
	if err != nil {
		logger.Printf("error reading from ZMQ socket: %v\n", err)
		return nil, err
	}

	parsed := &pb.ZMQPayload{}
	err = proto.Unmarshal(msg, parsed)
	if err != nil {
		logger.Printf("Failed to unmarshall ClientToStation: %v", err)
		return nil, err
	}

	conjureKeys, err := dd.GenSharedKeys(parsed.SharedSecret)

	// Register one or both of v4 and v6 based on support specified by the client
	var newRegs []*dd.DecoyRegistration

	if parsed.RegistrationPayload.GetV4Support() {
		reg, err := regManager.NewRegistration(parsed.RegistrationPayload, &conjureKeys, false)
		if err != nil {
			logger.Printf("Failed to create registration: %v", err)
			return nil, err
		}

		// log phantom IP, shared secret, ipv6 support
		logger.Printf("New registration: %v\n", reg.String())

		newRegs = append(newRegs, reg)
	}

	if parsed.RegistrationPayload.GetV6Support() {
		reg, err := regManager.NewRegistration(parsed.RegistrationPayload, &conjureKeys, true)
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
	regManager := dd.NewRegistrationManager()
	logger = regManager.Logger
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
