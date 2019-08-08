package main

import (
	"bytes"
	"fmt"
	"log"
	"net"
	"os"
	"syscall"

	dd "./lib"
	zmq "github.com/pebbe/zmq4"
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

	reg := regManager.CheckRegistration(originalDstIP)
	if reg == nil {
		logger.Printf("registration for %v not found", originalDstIP)
		return
	}

	proxyHandler := dd.ProxyFactory(reg, 0)
	if proxyHandler != nil {
		proxyHandler(reg, clientConn, originalDstIP)
	} else {
		logger.Printf("failed to initialize proxy, unknown or unimplemented protocol.")
		return
	}
}

func get_zmq_updates(regManager *dd.RegistrationManager) {
	logger := log.New(os.Stdout, "[ZMQ] ", log.Lmicroseconds)
	sub, err := zmq.NewSocket(zmq.SUB)
	if err != nil {
		logger.Printf("could not create new ZMQ socket: %v\n", err)
		return
	}
	defer sub.Close()

	bindAddr := "tcp://*:5591"
	sub.Bind(bindAddr)
	sub.SetSubscribe("")

	logger.Printf("listening on %v\n", bindAddr)

	for {

		ipAddr, reg, err := recieve_zmq_message(sub)
		if err != nil {
			continue
		}

		regManager.AddRegistration(*ipAddr, reg)
		logger.Printf("new registration: {dark decoy address=%v, covert=%v, mask=%v}\n",
			net.IP(ipAddr[:]).String(), reg.Covert, reg.Mask)
	}
}

func recieve_zmq_message(sub *zmq.Socket) (*[16]byte, *dd.DecoyRegistration, error) {
	var masterSecret [48]byte
	var ipAddr [16]byte
	var covertAddrLen, maskedAddrLen, flags [1]byte

	msg, err := sub.RecvBytes(0)
	if err != nil {
		logger.Printf("error reading from ZMQ socket: %v\n", err)
		return nil, nil, err
	}
	if len(msg) < 48+22 {
		logger.Printf("short message of size %v\n", len(msg))
		return nil, nil, fmt.Errorf("short message of size %v\n", len(msg))
	}

	msgReader := bytes.NewReader(msg)

	msgReader.Read(masterSecret[:])
	msgReader.Read(ipAddr[:])

	msgReader.Read(covertAddrLen[:])
	covertAddr := make([]byte, covertAddrLen[0])
	_, err = msgReader.Read(covertAddr)
	if err != nil {
		logger.Printf("short message with size %v didn't fit covert addr with length %v\n",
			len(msg), covertAddrLen[0])
		return nil, nil, err
	}

	msgReader.Read(maskedAddrLen[:])
	var maskedAddr []byte
	if maskedAddrLen[0] != 0 {
		maskedAddr = make([]byte, maskedAddrLen[0])
		_, err = msgReader.Read(maskedAddr)
		if err != nil {
			logger.Printf("short message with size %v didn't fit masked addr with length %v\n",
				len(msg), maskedAddrLen[0])
			return nil, nil, err
		}
	}
	msgReader.Read(flags[:])

	return &ipAddr, &dd.DecoyRegistration{
		MasterSecret: masterSecret,
		Covert:       string(covertAddr),
		Mask:         string(maskedAddr),
		Flags:        uint8(flags[0]),
	}, nil
}

var logger *log.Logger

func main() {
	regManager := dd.NewRegistrationManager()
	logger = regManager.Logger
	go get_zmq_updates(regManager)

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
		logger.Printf("[CONNECT] new connection from address: %v\n", ln.Addr())
		go handleNewConn(regManager, newConn)
	}
}
