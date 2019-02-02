package main

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	zmq "github.com/pebbe/zmq4"
	tls "github.com/refraction-networking/utls"
)

// replayableReaderConn could be replayed once by calling StartReplaying
type replayableReaderConn struct {
	net.Conn
	R            *bufio.Reader
	ReplayBuffer []byte
	ReplayState  uint8
	Replaying    bool
	Recording    bool
}

func (bc *replayableReaderConn) Read(b []byte) (n int, err error) {
	if bc.Replaying && len(bc.ReplayBuffer) > 0 {
		n = copy(b, bc.ReplayBuffer)
		bc.ReplayBuffer = bc.ReplayBuffer[n:]
	} else {
		n, err = bc.R.Read(b)
		if bc.Recording {
			bc.ReplayBuffer = append(bc.ReplayBuffer, b[:n]...)
		}
	}
	return
}

func (bc *replayableReaderConn) Peek(n int) ([]byte, error) {
	return bc.R.Peek(n)
}

func (bc *replayableReaderConn) StartReplaying() {
	bc.Replaying = true
	bc.Recording = false
}

func makeReplayableReaderConn(c net.Conn, r *bufio.Reader) *replayableReaderConn {
	return &replayableReaderConn{
		Conn:      c,
		R:         r,
		Recording: true,
	}
}

func parseSNI(b []byte) (string, error) {
	offset := 43
	if offset >= len(b) {
		return "", fmt.Errorf("short buf with length=%v", len(b))
	}
	sessionIdLen := int(b[offset])
	offset += 1
	offset += sessionIdLen

	if offset+1 >= len(b) {
		return "", fmt.Errorf("short buf, sessionIdLen was %v", sessionIdLen)
	}
	cipherSuitesLen := (int(b[offset]) << 8) + int(b[offset+1])
	offset += 2
	offset += cipherSuitesLen

	if offset >= len(b) {
		return "", fmt.Errorf("short buf, cipherSuitesLen was %v", cipherSuitesLen)
	}
	compressionMethodsLen := int(b[offset])
	offset += 1
	offset += compressionMethodsLen

	if offset > len(b) {
		return "", fmt.Errorf("short buf, compressionMethodsLen was %v", compressionMethodsLen)
	}

	offset += 2

	for {
		if offset == len(b) {
			return "", errors.New("no SNI extension found")
		}
		if offset+4 >= len(b) {
			return "", errors.New("short buf for extension header")
		}
		extId := (int(b[offset]) << 8) + int(b[offset+1])
		offset += 2

		extLen := (int(b[offset]) << 8) + int(b[offset+1])
		offset += 2

		if extId == 0 {
			if offset+extLen >= len(b) || offset+3 >= len(b) {
				return "", errors.New("short buf for SNI extension")
			}

			offset += 2
			nameType := b[offset]
			if nameType != 0 {
				return "", errors.New("type of SNI is not host_name")
			}

			offset += 1

			if offset+1 >= len(b) {
				return "", errors.New("short buf for host_name len")
			}
			nameLen := (int(b[offset]) << 8) + int(b[offset+1])

			offset += 2
			if offset+nameLen >= len(b) {
				return "", errors.New("short buf for host_name")
			}
			return string(b[offset : offset+nameLen]), nil
		}

		offset += extLen
	}
}

func createBuffer() interface{} {
	return make([]byte, 0, 32*1024)
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

func readConfigFromConnSnippet(c net.Conn) {
	var sniLen [1]byte
	var sni []byte
	var ipbuf [16]byte
	var portbuf [2]byte
	var sharedSecret [32]byte

	n, err := c.Read(sniLen[:])
	if err != nil {
		fmt.Printf("failed to read SNI Length: %v\n", err)
		return
	}
	if n != cap(sniLen) {
		fmt.Printf("failed to read SNI Length: got %v bytes, expected %v bytes\n", n, cap(sniLen))
		return
	}

	sni = make([]byte, sniLen[0])
	n, err = c.Read(sni[:])
	if err != nil {
		fmt.Printf("failed to read SNI: %v\n", err)
		return
	}
	if n != cap(sni) {
		fmt.Printf("failed to read SNI: got %v bytes, expected %v bytes\n", n, cap(sni))
		return
	}

	n, err = c.Read(ipbuf[:])
	if err != nil {
		fmt.Printf("failed to read IP: %v\n", err)
		return
	}
	if n != cap(ipbuf) {
		fmt.Printf("failed to read IP: got %v bytes, expected %v bytes\n", n, cap(ipbuf))
		return
	}

	n, err = c.Read(portbuf[:])
	if err != nil {
		fmt.Printf("failed to read port: %v\n", err)
		return
	}
	if n != cap(portbuf) {
		fmt.Printf("failed to read port: got %v bytes, expected %v bytes\n", n, cap(portbuf))
		return
	}

	n, err = c.Read(sharedSecret[:])
	if err != nil {
		fmt.Printf("failed to read sharedSecret: %v\n", err)
		return
	}
	if n != cap(sharedSecret) {
		fmt.Printf("failed to read sharedSecret: got %v bytes, expected %v bytes\n", n, cap(sharedSecret))
		return
	}

	targetTcpAddr := net.TCPAddr{IP: net.IP(ipbuf[:]),
		Port: int(binary.BigEndian.Uint16(portbuf[:])),
		Zone: ""}
	fmt.Printf("DEBUG Incoming connection to %v(%v)\n", sni, targetTcpAddr.String())
}

func handleNewConn(clientConn *net.TCPConn) {
	defer clientConn.Close()

	// WIP: will get those placeholders from zmq:
	maskHostPort := "microsoft.com:443"
	targetHostPort := "openrussia.org:443"
	masterSecret := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19,
		20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39,
		40, 41, 42, 43, 44, 45, 46, 47}

	// do the getsockopt
	// and check!

	maskedConn, err := net.DialTimeout("tcp", maskHostPort, time.Second*10)
	if err != nil {
		fmt.Printf("failed to dial %v: %v", maskHostPort, err)
		return
	}
	defer maskedConn.Close()
	tcpMaskedConn, ok := maskedConn.(*net.TCPConn)
	if !ok {
		fmt.Printf("failed to cast maskedConn %#v to TCPConn\n", maskedConn)
		return
	}

	// TODO: set timeouts

	var clientRandom, serverRandom [32]byte
	var cipherSuite uint16

	clientReplayableConn := makeReplayableReaderConn(clientConn, bufio.NewReader(clientConn))
	maskedConnBufReader := bufio.NewReader(tcpMaskedConn)

	// readFromClientAndParse returns when handshake is over
	// returned error signals if there were any errors reading/writing
	// may set clientRandom
	readFromClientAndParse := func() error {
		var clientRandomParsed, seenClientNonHandshakeMsg bool
		for !seenClientNonHandshakeMsg {
			const outerRecordHeaderLen = 5
			var outerTlsHeader []byte
			outerTlsHeader, err := clientReplayableConn.Peek(outerRecordHeaderLen)
			if err != nil {
				return err
			}
			outerRecordType := uint8(outerTlsHeader[0])
			// outerRecordTlsVersion := binary.BigEndian.Uint16(outerTlsHeader[1:3])
			outerRecordLength := binary.BigEndian.Uint16(outerTlsHeader[3:5])

			if outerRecordType == tlsRecordTypeApplicationData {

				return nil
			}

			if outerRecordType == tlsRecordTypeHandshake && !clientRandomParsed {
				// next 38 bytes include type(1), length(3), version(2), clientRandom(32)
				innerTlsHeader, err := clientReplayableConn.Peek(outerRecordHeaderLen + 38)
				if err != nil {
					return err
				}
				// innerRecordType := uint8(innerTlsHeader[5])
				// innerRecordTlsLength := binary.BigEndian.Uint24(innerTlsHeader[6:9])
				// innerRecordVersion := binary.BigEndian.Uint16(innerTlsHeader[10:11])
				copy(clientRandom[:], innerTlsHeader[11:])
				clientRandomParsed = true
			} else {
				seenClientNonHandshakeMsg = true
			}
			_, err = io.CopyN(tcpMaskedConn, clientReplayableConn, outerRecordHeaderLen+int64(outerRecordLength))
			if err != nil {
				return err
			}
		}
		return nil
	}

	// readFromServerAndParse returns when handshake is over
	// returned error signals if there were any errors reading/writing
	// may set serverRandom
	readFromServerAndParse := func() error {
		for {
			const outerRecordHeaderLen = 5
			tlsHeader, err := maskedConnBufReader.Peek(outerRecordHeaderLen)
			if err != nil {
				return err
			}
			outerRecordType := uint8(tlsHeader[0])
			// outerRecordTlsVersion := binary.BigEndian.Uint16(tlsHeader[1:3])
			outerRecordLength := binary.BigEndian.Uint16(tlsHeader[3:5])

			if outerRecordType != tlsRecordTypeHandshake {
				return nil
			}

			// next 38 bytes are type(1), length(3), version(2), then serverRandom(32)
			tlsHeader, err = maskedConnBufReader.Peek(outerRecordHeaderLen + 39)
			if err != nil {
				return err
			}
			innerRecordType := uint8(tlsHeader[5])
			// innerRecordTlsLength := binary.BigEndian.Uint24(tlsHeader[6:9])
			// innerRecordVersion := binary.BigEndian.Uint16(tlsHeader[10:11])

			if innerRecordType == TlsHandshakeTypeServerHello {
				copy(serverRandom[:], tlsHeader[11:43])
				sessionIdLen := int(tlsHeader[43])
				tlsHeader, err = maskedConnBufReader.Peek(outerRecordHeaderLen + 39 + sessionIdLen + 2)
				if err != nil {
					return err
				}
				cipherSuite = binary.BigEndian.Uint16(tlsHeader[outerRecordHeaderLen+39+sessionIdLen : outerRecordHeaderLen+39+sessionIdLen+2])
			}

			// then goes sessionIdLen(1), sessionId(sessionIdLen), cipherSuite(2)
			// then compressionMethod(1), extensionsLen(2), extensions(extensionsLen)

			_, err = io.CopyN(tcpMaskedConn, maskedConnBufReader, outerRecordHeaderLen+int64(outerRecordLength))
			if err != nil {
				return err
			}
		}
	}

	go readFromClientAndParse()
	err = readFromServerAndParse()
	if err != nil {
		// TODO: well-formated error failed to read from masked server [from->to] err
		fmt.Println(err)
		return
	}

	var finalTargetConn net.Conn // either connection to the masked site or to real requested target
	var finalClientConn net.Conn // original conn or forgedTlsConn

	finalTargetConn = tcpMaskedConn
	finalClientConn = clientReplayableConn

	// check if we can forge a tls connection
	forgedTlsConn := tls.MakeConnWithCompleteHandshake(
		clientReplayableConn, tls.VersionTLS12,
		cipherSuite, masterSecret, clientRandom[:], serverRandom[:], false)
	buf := bufferPool.Get().([]byte)
	_, err = forgedTlsConn.Read(buf)
	if err != nil {
		// TODO: well-formated error failed to read from forged conn [from->to] err
		fmt.Println(err)
		clientReplayableConn.StartReplaying()
	} else {
		// success!
		targetConn, err := net.Dial("tcp", targetHostPort)
		if err != nil {
			// TODO: well-formated error failed to dial forget conn [from->to] err
			fmt.Println(err)
			clientReplayableConn.StartReplaying()
		} else {
			defer targetConn.Close()
			finalClientConn = forgedTlsConn
			finalTargetConn = targetConn
		}
	}

	wg := sync.WaitGroup{}
	oncePrintErr := sync.Once{}
	wg.Add(2)
	halfProxy := func(in, out net.Conn) {
		buf := bufferPool.Get().([]byte)
		_, err := io.CopyBuffer(out, in, buf)
		oncePrintErr.Do(
			func() {
				fmt.Printf("[INFO] stopping forwarding [%v] -> [%v]: %v\n",
					in.RemoteAddr(), out.RemoteAddr(), err)
			})
		if closeWriter, ok := out.(interface {
			CloseWrite() error
		}); ok {
			closeWriter.CloseWrite()
		}
		if closeReader, ok := in.(interface {
			CloseRead() error
		}); ok {
			closeReader.CloseRead()
		}
		wg.Done()
	}

	go halfProxy(finalTargetConn, finalClientConn)
	go halfProxy(finalClientConn, finalTargetConn)
	wg.Wait()
	// closes for all the things are deferred
	return
}

func get_zmq_updates() {

	sub, err := zmq.NewSocket(zmq.SUB)
	if err != nil {
		fmt.Printf("Could not create new ZMQ socket: %v\n", err)
		return
	}
	defer sub.Close()

	sub.Bind("tcp://*:5591")
	sub.SetSubscribe("")

	fmt.Printf("[INFO] ZMQ listening on *:5591\n")
	for {
		msg, err := sub.Recv(0)
		if err != nil {
			fmt.Printf("Error reading from ZMQ socket: %v\n", err)
		}
		// First 16 bytes are the seed, second 16 are the dark decoy address (derived from the seed)
		seed := []byte(msg)[0:16]
		dst_ip := []byte(msg)[16:32]
		fmt.Printf("Got ZMQ message: seed %v, dst_ip %v\n", seed, dst_ip)
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
	fmt.Printf("[INFO] Listening on %v\n", ln.Addr())

	for {
		newConn, err := ln.AcceptTCP()
		if err != nil {
			fmt.Printf("ERROR failed to AcceptTCP on %v: %v\n", ln.Addr(), err)
			return // continue?
		}

		go handleNewConn(newConn)
	}
}
