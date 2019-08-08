package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"

	zmq "github.com/pebbe/zmq4"
	dd "./lib"
	"github.com/refraction-networking/utls"
)

// bufferedReaderConn allows to combine *bufio.Reader(conn) and *conn into one struct.
// Implements net.Conn
type bufferedReaderConn struct {
	net.Conn
	R *bufio.Reader
}

func (bc *bufferedReaderConn) Read(b []byte) (n int, err error) {
	return bc.R.Read(b)
}

func (bc *bufferedReaderConn) Peek(n int) ([]byte, error) {
	return bc.R.Peek(n)
}

func (bc *bufferedReaderConn) CloseWrite() error {
	if closeWriter, ok := bc.Conn.(interface {
		CloseWrite() error
	}); ok {
		return closeWriter.CloseWrite()
	} else {
		return errors.New("not a CloseWriter")
	}
}

func (bc *bufferedReaderConn) CloseRead() error {
	if closeReader, ok := bc.Conn.(interface {
		CloseRead() error
	}); ok {
		return closeReader.CloseRead()
	} else {
		return errors.New("not a CloseReader")
	}
}

func makeBufferedReaderConn(c net.Conn, r *bufio.Reader) *bufferedReaderConn {
	return &bufferedReaderConn{
		Conn: c,
		R:    r,
	}
}

func createBuffer() interface{} {
	return make([]byte, 32*1024)
}

var bufferPool = sync.Pool{New: createBuffer}

const (
	tlsRecordTypeChangeCipherSpec = byte(20)
	tlsRecordTypeAlert            = byte(21)
	tlsRecordTypeHandshake        = byte(22)
	tlsRecordTypeApplicationData  = byte(23)
	tlsRecordTypeHearbeat         = byte(24)
)

const (
	TlsHandshakeTypeHelloRequest       = byte(0)
	TlsHandshakeTypeClientHello        = byte(1)
	TlsHandshakeTypeServerHello        = byte(2)
	TlsHandshakeTypeNewSessionTicket   = byte(4)
	TlsHandshakeTypeCertificate        = byte(11)
	TlsHandshakeTypeServerKeyExchange  = byte(12)
	TlsHandshakeTypeCertificateRequest = byte(13)
	TlsHandshakeTypeServerHelloDone    = byte(14)
	TlsHandshakeTypeCertificateVerify  = byte(15)
	TlsHandshakeTypeClientKeyExchange  = byte(16)
	TlsHandshakeTypeFinished           = byte(20)
	TlsHandshakeTypeCertificateStatus  = byte(22)
	TlsHandshakeTypeNextProtocol       = byte(67)
)

const (
	tdFlagUploadOnly  = uint8(1 << 7)
	tdFlagDarkDecoy   = uint8(1 << 6)
	tdFlagProxyHeader = uint8(1 << 1)
	tdFlagUseTIL      = uint8(1 << 0)
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

func threeWayProxy(reg *dd.DecoyRegistration, clientConn *net.TCPConn, originalDstIP net.IP) {
	maskHostPort := reg.Mask
	if _, mPort, err := net.SplitHostPort(maskHostPort); err != nil {
		maskHostPort = net.JoinHostPort(maskHostPort, "443")
	} else {
		if mPort != "443" {
			logger.Printf("port %v is not allowed in masked host", mPort)
			return
		}
	}
	targetHostPort := reg.Covert
	masterSecret := reg.MasterSecret[:]
	originalDst := originalDstIP.String()
	notReallyOriginalSrc := clientConn.LocalAddr().String()

	flowDescription := fmt.Sprintf("[%s -> %s(%v) -> %s] ",
		notReallyOriginalSrc, originalDst, maskHostPort, targetHostPort)
	logger := log.New(os.Stdout, flowDescription, log.Lmicroseconds)
	logger.Println("new flow")

	maskedConn, err := net.DialTimeout("tcp", maskHostPort, time.Second*10)
	if err != nil {
		logger.Printf("failed to dial masked host: %v", err)
		return
	}
	defer maskedConn.Close()

	// TODO: set timeouts

	var clientRandom, serverRandom [32]byte
	var cipherSuite uint16

	clientBufConn := makeBufferedReaderConn(clientConn, bufio.NewReader(clientConn))
	serverBufConn := makeBufferedReaderConn(maskedConn, bufio.NewReader(maskedConn))

	// readFromClientAndParse returns when handshake is over
	// returned error signals if there were any errors reading/writing
	// If readFromClientAndParse returns successfully, following variables will be set:
	//    clientRandom: Client Random
	//    clientBufferedRecordSize: size of TLS record(+header) that will be sitting in clientBufConn
	clientBufferedRecordSize := 0
	readFromClientAndParse := func() error {
		var clientRandomParsed bool
		for {
			const outerRecordHeaderLen = int(5)
			var outerTlsHeader []byte
			outerTlsHeader, err := clientBufConn.Peek(outerRecordHeaderLen)
			if err != nil {
				return err
			}
			outerRecordType := uint8(outerTlsHeader[0])
			// outerRecordTlsVersion := binary.BigEndian.Uint16(outerTlsHeader[1:3])
			outerRecordLength := int(binary.BigEndian.Uint16(outerTlsHeader[3:5]))

			if outerRecordType != tlsRecordTypeHandshake && outerRecordType != tlsRecordTypeChangeCipherSpec {
				clientBufferedRecordSize = outerRecordHeaderLen + outerRecordLength
				return nil
			}

			if outerRecordType == tlsRecordTypeHandshake && !clientRandomParsed {
				// next 38 bytes include type(1), length(3), version(2), clientRandom(32)
				innerTlsHeader, err := clientBufConn.Peek(outerRecordHeaderLen + 38)
				if err != nil {
					return err
				}
				// innerRecordType := uint8(innerTlsHeader[5])
				// innerRecordTlsLength := binary.BigEndian.Uint24(innerTlsHeader[6:9])
				// innerRecordVersion := binary.BigEndian.Uint16(innerTlsHeader[10:11])
				copy(clientRandom[:], innerTlsHeader[11:])
				clientRandomParsed = true
			}

			_, err = io.CopyN(serverBufConn, clientBufConn, int64(outerRecordHeaderLen+outerRecordLength))
			if err != nil {
				return err
			}
		}
	}

	// readFromServerAndParse returns when handshake is over
	// returned error signals if there were any errors reading/writing
	// may set serverRandom
	readFromServerAndParse := func() error {
		for {
			const outerRecordHeaderLen = 5
			tlsHeader, err := serverBufConn.Peek(outerRecordHeaderLen)
			if err != nil {
				return err
			}
			outerRecordType := uint8(tlsHeader[0])
			// outerRecordTlsVersion := binary.BigEndian.Uint16(tlsHeader[1:3])
			outerRecordLength := binary.BigEndian.Uint16(tlsHeader[3:5])

			if outerRecordType != tlsRecordTypeHandshake && outerRecordType != tlsRecordTypeChangeCipherSpec {
				return nil
			}

			if outerRecordLength >= 39 {
				// next 38 bytes are type(1), length(3), version(2), then serverRandom(32)
				tlsHeader, err = serverBufConn.Peek(outerRecordHeaderLen + 39)
				if err != nil {
					return err
				}
				innerRecordType := uint8(tlsHeader[5])
				// innerRecordTlsLength := binary.BigEndian.Uint24(tlsHeader[6:9])
				// innerRecordVersion := binary.BigEndian.Uint16(tlsHeader[10:11])

				if innerRecordType == TlsHandshakeTypeServerHello {
					copy(serverRandom[:], tlsHeader[11:43])
					sessionIdLen := int(tlsHeader[43])
					tlsHeader, err = serverBufConn.Peek(outerRecordHeaderLen + 39 + sessionIdLen + 2)
					if err != nil {
						return err
					}
					cipherSuite = binary.BigEndian.Uint16(tlsHeader[outerRecordHeaderLen+39+sessionIdLen : outerRecordHeaderLen+39+sessionIdLen+2])
				}
				// then goes compressionMethod(1), extensionsLen(2), extensions(extensionsLen)
			}

			_, err = io.CopyN(clientBufConn, serverBufConn, outerRecordHeaderLen+int64(outerRecordLength))
			if err != nil {
				return err
			}
		}
	}

	serverErrChan := make(chan error)
	go func() {
		_err := readFromServerAndParse()
		serverErrChan <- _err
	}()

	err = readFromClientAndParse()
	if err != nil {
		logger.Printf("failed to readFromClientAndParse: %v", err)
		return
	}

	// at this point:
	//   readFromClientAndParse exited and there's unread non-handshake data in the conn
	//   readFromServerAndParse is still in Peek()
	firstAppData, err := clientBufConn.Peek(clientBufferedRecordSize)
	if err != nil {
		logger.Printf("failed to peek into first app data: %v", err)
		return
	}

	p1, p2 := net.Pipe()

	inMemTlsConn := tls.MakeConnWithCompleteHandshake(
		p1, tls.VersionTLS12, // TODO: parse version!
		cipherSuite, masterSecret, clientRandom[:], serverRandom[:], false)

	go func() {
		p2.Write(firstAppData)
		p2.Close()
	}()

	var finalTargetConn net.Conn // either connection to the masked site or to real requested target
	var finalClientConn net.Conn // original conn or forgedTlsConn

	finalTargetConn = serverBufConn
	finalClientConn = clientBufConn

	decryptedFirstAppData, err := ioutil.ReadAll(inMemTlsConn)
	if err != nil || len(decryptedFirstAppData) == 0 {
		logger.Printf("not tagged: %s", err)
	} else {
		// almost success! now need to dial targetHostPort (TODO: do it in advance!)
		targetConn, err := net.Dial("tcp", targetHostPort)
		if err != nil {
			logger.Printf("failed to dial target: %s", err)
		} else {
			logger.Printf("flow is tagged")
			defer targetConn.Close()
			serverBufConn.Close()
			forgedTlsConn := tls.MakeConnWithCompleteHandshake(
				clientBufConn, tls.VersionTLS12,
				cipherSuite, masterSecret, clientRandom[:], serverRandom[:], false)
			finalClientConn = forgedTlsConn
			finalTargetConn = targetConn
		}
	}

	wg := sync.WaitGroup{}
	oncePrintErr := sync.Once{}
	wg.Add(2)

	go halfPipe(finalClientConn, finalTargetConn, wg, oncePrintErr)

	go func() {
		// wait for readFromServerAndParse to exit first, as it probably haven't seen appdata yet
		select {
		case _ = <-serverErrChan:
			halfPipe(finalClientConn, finalTargetConn, wg, oncePrintErr)
		case <-time.After(10 * time.Second):
			finalClientConn.Close()
			wg.Done()
		}
	}()
	wg.Wait()
	// closes for all the things are deferred
	return
}

// this function is kinda ugly, uses undecorated logger, and passes things around it doesn't have to pass around
// TODO: refactor
func halfPipe(src, dst net.Conn, wg sync.WaitGroup, oncePrintErr sync.Once) {
	buf := bufferPool.Get().([]byte)
	_, err := io.CopyBuffer(dst, src, buf)
	oncePrintErr.Do(
		func() {
			if err == nil {
				logger.Printf("gracefully stopping forwarding from %v", src.RemoteAddr())
			} else {
				logger.Printf("stopping forwarding from %v due to error: %v", src.RemoteAddr(), err)
			}
		})
	if closeWriter, ok := dst.(interface {
		CloseWrite() error
	}); ok {
		closeWriter.CloseWrite()
	} else {
		dst.Close()
	}

	if closeReader, ok := src.(interface {
		CloseRead() error
	}); ok {
		closeReader.CloseRead()
	} else {
		src.Close()
	}
	wg.Done()
}

func handleNewConn(clientConn *net.TCPConn) {
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

	reg := registeredDecoys.CheckRegistration(originalDstIP)
	if reg == nil {
		logger.Printf("registration for %v not found", originalDstIP)
		return
	}

	//threeWayProxy(reg, clientConn, originalDstIP)
	twoWayProxy(reg, clientConn, originalDstIP)
}

func twoWayProxy(reg *dd.DecoyRegistration, clientConn *net.TCPConn, originalDstIP net.IP) {
	var err error
	originalDst := originalDstIP.String()
	notReallyOriginalSrc := clientConn.LocalAddr().String()
	flowDescription := fmt.Sprintf("[%s -> %s (covert=%s)] ",
		notReallyOriginalSrc, originalDst, reg.Covert)
	logger := log.New(os.Stdout, flowDescription, log.Lmicroseconds)
	logger.Println("new flow")

	covertConn, err := net.Dial("tcp", reg.Covert)
	if err != nil {
		logger.Printf("failed to dial target: %s", err)
		return
	}
	defer covertConn.Close()

	if reg.Flags & tdFlagProxyHeader == 1 {
		err = writePROXYHeader(covertConn, clientConn.RemoteAddr().String())
		if err != nil {
			logger.Printf("failed to send PROXY header to covert: %s", err)
			return
		}
	}

	wg := sync.WaitGroup{}
	oncePrintErr := sync.Once{}
	wg.Add(2)

	go halfPipe(clientConn, covertConn, wg, oncePrintErr)
	go halfPipe(covertConn, clientConn, wg, oncePrintErr)
	wg.Wait()
}

func get_zmq_updates() {
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

		registeredDecoys.Register(*ipAddr, reg)
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
		Flags:		  uint8(flags[0]),
	}, nil
}

var registeredDecoys *dd.RegisteredDecoys
var logger *log.Logger

func main() {
	logger = log.New(os.Stdout, "", log.Lmicroseconds)
	registeredDecoys = dd.NewRegisteredDecoys()
	go get_zmq_updates()

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
		go handleNewConn(newConn)
	}
}

func writePROXYHeader(conn net.Conn, originalIPPort string) error {
	if len(originalIPPort) == 0 {
		return errors.New("can't write PROXY header: empty IP")
	}
	transportProtocol := "TCP4"
	if !strings.Contains(originalIPPort, ".") {
		transportProtocol = "TCP6"
	}
	host, port, err := net.SplitHostPort(originalIPPort)
	if err != nil {
		return err
	}
	proxyHeader := fmt.Sprintf("PROXY %s %s 127.0.0.1 %s 1234\r\n", transportProtocol, host, port)
	_, err = conn.Write([]byte(proxyHeader))
	return err
}
