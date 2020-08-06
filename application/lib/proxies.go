package lib

import (
	"bufio"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	tls "github.com/refraction-networking/utls"
)

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
	TdFlagUploadOnly  = uint8(1 << 7)
	TdFlagDarkDecoy   = uint8(1 << 6)
	TdFlagProxyHeader = uint8(1 << 1)
	TdFlagUseTIL      = uint8(1 << 0)
)

var bufferPool = sync.Pool{New: createBuffer}

func ProxyFactory(reg *DecoyRegistration, proxyProtocol uint) func(*DecoyRegistration, *net.TCPConn, net.IP) {
	switch proxyProtocol {
	case 0:
		return func(reg *DecoyRegistration, clientConn *net.TCPConn, originalDstIP net.IP) {
			twoWayProxy(reg, clientConn, originalDstIP)
		}
	case 1:
		return func(reg *DecoyRegistration, clientConn *net.TCPConn, originalDstIP net.IP) {
			threeWayProxy(reg, clientConn, originalDstIP)
		}
	case 2:
		return func(reg *DecoyRegistration, clientConn *net.TCPConn, originalDstIP net.IP) {
			// Obfs4 handler
			return
		}
	default:
		return func(reg *DecoyRegistration, clientConn *net.TCPConn, originalDstIP net.IP) {
			return
		}
	}
}

type sessionStats struct {
	From     string
	Duration int64
	Written  int64
	Tag      string
	Err      string
}

// this function is kinda ugly, uses undecorated logger, and passes things around it doesn't have to pass around
// TODO: refactor
func halfPipe(src, dst net.Conn,
	wg *sync.WaitGroup,
	oncePrintErr sync.Once,
	logger *log.Logger,
	tag string) {

	var proxyStartTime = time.Now()

	buf := bufferPool.Get().([]byte)
	written, err := io.CopyBuffer(dst, src, buf)
	oncePrintErr.Do(
		func() {
			proxyEndTime := time.Since(proxyStartTime)
			if err == nil {
				stats := sessionStats{
					From:     src.RemoteAddr().String(),
					Duration: int64(proxyEndTime / time.Millisecond),
					Written:  written,
					Tag:      tag,
					Err:      ""}
				stats_str, _ := json.Marshal(stats)
				logger.Printf("gracefully stopping forwarding %s", stats_str)
			} else {
				stats := sessionStats{
					From:     src.RemoteAddr().String(),
					Duration: int64(proxyEndTime / time.Millisecond),
					Written:  written,
					Tag:      tag,
					Err:      err.Error()}
				stats_str, _ := json.Marshal(stats)
				logger.Printf("stopping forwarding due to err %s", stats_str)
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

func readAtMost(conn *net.TCPConn, buf []byte) (int, error) {
	tot := 0
	for tot < len(buf) {
		n, err := conn.Read(buf[tot:])
		if err != nil {
			return n, err
		}
		tot += n
	}
	return tot, nil
}

func MinTransportProxy(regManager *RegistrationManager, clientConn *net.TCPConn, originalDstIP net.IP) {

	originalDst := originalDstIP.String()
	originalSrc := clientConn.RemoteAddr().String()
	flowDescription := fmt.Sprintf("%s -> %s ", originalSrc, originalDst)
	logger := log.New(os.Stdout, "[MIN] "+flowDescription, log.Ldate|log.Lmicroseconds)

	logger.Printf("new connection (%d potential registrations)", regManager.CountRegistrations(&originalDstIP))

	possibleHmac := make([]byte, 32)
	n, err := readAtMost(clientConn, possibleHmac)
	if err != nil || n < 32 {
		logger.Printf("failed to read hmacId, read_bytes: %d, error: %s", n, err)
		return
	}

	reg := regManager.CheckRegistration(&originalDstIP, possibleHmac)
	if reg == nil {
		logger.Printf("registration not found {phantom: %v, hmac: %s}\n", originalDstIP, hex.EncodeToString(possibleHmac))
		return
	}
	// If we are here, this is our transport (TODO: signal in output channel for it)
	logger.Printf("registration found {reg_id: %s, phantom: %s, hmac: %s, covert: %s}\n", reg.IDString(), originalDstIP, hex.EncodeToString(possibleHmac), reg.Covert)
	logger.SetPrefix(fmt.Sprintf("[MIN] %s ", reg.IDString()))

	covertConn, err := net.Dial("tcp", reg.Covert)
	if err != nil {
		logger.Printf("failed to dial target: %s", err)
		return
	}
	defer covertConn.Close()

	if reg.Flags.GetProxyHeader() {
		err = writePROXYHeader(covertConn, clientConn.RemoteAddr().String())
		if err != nil {
			logger.Printf("failed to send PROXY header to covert: %s", err)
			return
		}
	}

	wg := sync.WaitGroup{}
	oncePrintErr := sync.Once{}
	wg.Add(2)

	go halfPipe(clientConn, covertConn, &wg, oncePrintErr, logger, "Up")
	go halfPipe(covertConn, clientConn, &wg, oncePrintErr, logger, "Down")
	wg.Wait()
}

func twoWayProxy(reg *DecoyRegistration, clientConn *net.TCPConn, originalDstIP net.IP) {
	var err error
	originalDst := originalDstIP.String()
	notReallyOriginalSrc := clientConn.RemoteAddr().String()
	flowDescription := fmt.Sprintf("[%s -> %s (covert=%s)] ",
		notReallyOriginalSrc, originalDst, reg.Covert)
	logger := log.New(os.Stdout, "[2WP] "+flowDescription, log.Ldate|log.Lmicroseconds)
	logger.Println("new flow")

	covertConn, err := net.Dial("tcp", reg.Covert)
	if err != nil {
		logger.Printf("failed to dial target: %s", err)
		return
	}
	defer covertConn.Close()

	if reg.Flags.GetProxyHeader() {
		err = writePROXYHeader(covertConn, clientConn.RemoteAddr().String())
		if err != nil {
			logger.Printf("failed to send PROXY header to covert: %s", err)
			return
		}
	}

	wg := sync.WaitGroup{}
	oncePrintErr := sync.Once{}
	wg.Add(2)

	go halfPipe(clientConn, covertConn, &wg, oncePrintErr, logger, "Up")
	go halfPipe(covertConn, clientConn, &wg, oncePrintErr, logger, "Down")
	wg.Wait()
}

func writePROXYHeader(conn net.Conn, originalIPPort string) error {
	logger := log.New(os.Stdout, "[2WP] ", log.Ldate|log.Lmicroseconds)
	logger.Println("Writing Proxy Header")
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

func threeWayProxy(reg *DecoyRegistration, clientConn *net.TCPConn, originalDstIP net.IP) {
	maskHostPort := reg.Mask
	targetHostPort := reg.Covert
	masterSecret := reg.keys.MasterSecret[:]
	originalDst := originalDstIP.String()
	notReallyOriginalSrc := clientConn.LocalAddr().String()

	flowDescription := fmt.Sprintf("[%s -> %s(%v) -> %s] ",
		notReallyOriginalSrc, originalDst, maskHostPort, targetHostPort)
	logger := log.New(os.Stdout, "[3WP] "+flowDescription, log.Ldate|log.Lmicroseconds)

	if _, mPort, err := net.SplitHostPort(maskHostPort); err != nil {
		maskHostPort = net.JoinHostPort(maskHostPort, "443")
	} else {
		if mPort != "443" {
			logger.Printf("port %v is not allowed in masked host", mPort)
			return
		}
	}
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

	go halfPipe(finalClientConn, finalTargetConn, &wg, oncePrintErr, logger, "Up")

	go func() {
		// wait for readFromServerAndParse to exit first, as it probably haven't seen appdata yet
		select {
		case _ = <-serverErrChan:
			halfPipe(finalClientConn, finalTargetConn, &wg, oncePrintErr, logger, "Down")
		case <-time.After(10 * time.Second):
			finalClientConn.Close()
			wg.Done()
		}
	}()
	wg.Wait()
	// closes for all the things are deferred
	return
}
