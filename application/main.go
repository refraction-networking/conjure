package main

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"sync"
	"syscall"
	"time"

	zmq "github.com/pebbe/zmq4"
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

func getOriginalDst(fd uintptr) (string, error) {
	const SO_ORIGINAL_DST = 80
	fmt.Println("[DEBUG] getSockOpt variants:")
	sockOpt, err := syscall.GetsockoptIPv6Mreq(int(fd), syscall.IPPROTO_IPV6, SO_ORIGINAL_DST)
	fmt.Println("  ", sockOpt, fd, err)
	sockOpt2, err := syscall.GetsockoptIPv6Mreq(int(fd), syscall.IPPROTO_IP, SO_ORIGINAL_DST)
	fmt.Println("  ", sockOpt2, fd, err)
	sockOpt3, err := syscall.GetsockoptIPMreq(int(fd), syscall.IPPROTO_IP, SO_ORIGINAL_DST)
	fmt.Println("  ", sockOpt3, fd, err)
	sockOpt4, err := syscall.GetsockoptIPMreq(int(fd), syscall.IPPROTO_IP, SO_ORIGINAL_DST)
	fmt.Println("  ", sockOpt4, fd, err)

	// TODO: parse the original dst and return
	return "", err
}

func handleNewConn(clientConn *net.TCPConn) {
	defer clientConn.Close()

	fd, err := clientConn.File()
	if err != nil {
		fmt.Printf("failed to get file descriptor on clientConn: %v\n", err)
		return
	}

	// WIP: will get those placeholders from zmq:
	maskHostPort := "google.com:443"
	targetHostPort := "twitter.com:443"
	masterSecret := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19,
		20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39,
		40, 41, 42, 43, 44, 45, 46, 47}
	// TODO: get the targetHostPort, maskHostPort, and masterSecret from ZMQ, depending on originalAddr
	// TODO: if NOT port 443: just forward things and return

	_ = fd
	// getOriginalDst(fd.Fd())
	// TODO: fill in actual original dst and src, those are placeholders
	originalDst := clientConn.RemoteAddr().String()
	originalSrc := clientConn.LocalAddr().String()

	flowDescription := fmt.Sprintf("[%s -> %s(%v) -> %s] ",
		originalSrc, originalDst, maskHostPort, targetHostPort)
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
	halfProxy := func(src, dst net.Conn) {
		buf := bufferPool.Get().([]byte)
		_, err = io.CopyBuffer(dst, src, buf)
		oncePrintErr.Do(
			func() {
				if err == nil {
					logger.Printf("gracefully stopping forwarding from %v", src.RemoteAddr())
				} else {
					logger.Printf("stopping forwarding from %v due to error: %v", src.RemoteAddr(), err)
				}
			})
		//if closeWriter, ok := dst.(interface {
		//	CloseWrite() error
		//}); ok {
		//	closeWriter.CloseWrite()
		//}
		//
		//if closeReader, ok := src.(interface {
		//	CloseRead() error
		//}); ok {
		//	closeReader.CloseRead()
		//}
		wg.Done()
	}

	go halfProxy(finalClientConn, finalTargetConn)

	go func() {
		// wait for readFromServerAndParse to exit first, as it probably haven't seen appdata yet
		select {
		case _ = <-serverErrChan:
			halfProxy(finalTargetConn, finalClientConn)
		case <-time.After(10 * time.Second):
			finalClientConn.Close()
			wg.Done()
		}
	}()
	wg.Wait()
	// closes for all the things are deferred
	return
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
		msg, err := sub.Recv(0)
		if err != nil {
			logger.Printf("error reading from ZMQ socket: %v\n", err)
		}
		// First 16 bytes are the seed, second 16 are the dark decoy address (derived from the seed)
		seed := []byte(msg)[0:16]
		dst_ip := []byte(msg)[16:32]
		logger.Printf("new registration: seed %v, dst_ip %v\n", seed, dst_ip)
	}
}

func main() {
	go get_zmq_updates()

	listenAddr := &net.TCPAddr{IP: nil, Port: 41245, Zone: ""}
	ln, err := net.ListenTCP("tcp", listenAddr)
	if err != nil {
		fmt.Printf("failed to listen on %v: %v\n", listenAddr, err)
		return
	}
	defer ln.Close()
	fmt.Printf("[STARTUP] Listening on %v\n", ln.Addr())

	for {
		newConn, err := ln.AcceptTCP()
		if err != nil {
			fmt.Printf("[ERROR] failed to AcceptTCP on %v: %v\n", ln.Addr(), err)
			return // continue?
		}

		go handleNewConn(newConn)
	}
}
