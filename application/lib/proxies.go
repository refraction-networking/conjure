package lib

import (
	"bufio"
	"encoding/binary"
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
	Duration int64
	Written  int64
	Tag      string
	Err      string
}

// this function is kinda ugly, uses undecorated logger, and passes things around it doesn't have to pass around
// TODO: refactor
func halfPipe(src, dst net.Conn,
	wg *sync.WaitGroup,
	oncePrintErr *sync.Once,
	logger *log.Logger,
	tag string) {

	var proxyStartTime = time.Now()

	// using io.CopyBuffer doesn't let us see
	// bytes / second (until very end of connect, then only avg)
	// But io.CopyBuffer is very performant:
	// actually doesn't use a buffer at all, just splices sockets
	// together at the kernel level.
	//
	// We could try to use io.CopyN in a loop or something that
	// gives us occasional bytes. CopyN would not splice, though
	// (uses a LimitedReader that only calls Read)
	//buf := bufferPool.Get().([]byte)
	//written, err := io.CopyBuffer(dst, src, buf)

	// On closer examination, it seems this code below seems about
	// as performant. It's not using splice, but for CO comcast / curveball:
	//				io.CopyBuffer	Read/Write
	// curveball CPU	~2%				~2%
	// DL 40MB time		~11.5s			~11.6s
	// So while io.CopyBuffer is faster, it's not significantly faster

	// If we run into perf problems, we can revert

	written, err := func() (totWritten int64, err error) {
		buf := make([]byte, 32*1024)
		for {
			nr, er := src.Read(buf)
			if nr > 0 {
				nw, ew := dst.Write(buf[0:nr])
				totWritten += int64(nw)
				// Update stats:
				if strings.HasPrefix(tag, "Up") {
					Stat().AddBytesUp(int64(nw))
				} else {
					Stat().AddBytesDown(int64(nw))
				}

				if ew != nil {
					if ew != io.EOF {
						err = ew
					}
					break
				}
				if nw != nr {
					err = io.ErrShortWrite
					break
				}
			}
			if er != nil {
				if er != io.EOF {
					err = er
				}
				break
			}
		}
		return totWritten, err

	}()

	// Close dst
	if closeWriter, ok := dst.(interface {
		CloseWrite() error
	}); ok {
		closeWriter.CloseWrite()
	} else {
		dst.Close()
	}

	// Close src
	if closeReader, ok := src.(interface {
		CloseRead() error
	}); ok {
		closeReader.CloseRead()
	} else {
		src.Close()
	}

	// Compute/log stats

	proxyEndTime := time.Since(proxyStartTime)
	stats := sessionStats{
		Duration: int64(proxyEndTime / time.Millisecond),
		Written:  written,
		Tag:      tag,
		Err:      ""}
	if err != nil {
		stats.Err = err.Error()
	}
	stats_str, _ := json.Marshal(stats)
	logger.Printf("stopping forwarding %s", stats_str)
	/*
		if strings.HasPrefix(tag, "Up") {
			Stat().AddBytesUp(written)
		} else {
			Stat().AddBytesDown(written)
		}*/

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

func Proxy(reg *DecoyRegistration, clientConn net.Conn, logger *log.Logger) {
	covertConn, err := net.Dial("tcp", reg.Covert)
	if err != nil {
		logger.Printf("failed to dial target: %s", err)
		return
	}
	defer covertConn.Close()

	if reg.Flags.GetProxyHeader() {
		err = writePROXYHeader(covertConn, clientConn.RemoteAddr().String())
		if err != nil {
			logger.Printf("failed to send PROXY header: %s", err)
			return
		}
	}

	wg := sync.WaitGroup{}
	oncePrintErr := sync.Once{}
	wg.Add(2)

	go halfPipe(clientConn, covertConn, &wg, &oncePrintErr, logger, "Up "+reg.IDString())
	go halfPipe(covertConn, clientConn, &wg, &oncePrintErr, logger, "Down "+reg.IDString())
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

	go halfPipe(clientConn, covertConn, &wg, &oncePrintErr, logger, "Up")
	go halfPipe(covertConn, clientConn, &wg, &oncePrintErr, logger, "Down")
	wg.Wait()
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

func threeWayProxy(reg *DecoyRegistration, clientConn *net.TCPConn, originalDstIP net.IP) {
	maskHostPort := reg.Mask
	targetHostPort := reg.Covert
	masterSecret := reg.Keys.MasterSecret[:]
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

	go halfPipe(finalClientConn, finalTargetConn, &wg, &oncePrintErr, logger, "Up")

	go func() {
		// wait for readFromServerAndParse to exit first, as it probably haven't seen appdata yet
		select {
		case _ = <-serverErrChan:
			halfPipe(finalClientConn, finalTargetConn, &wg, &oncePrintErr, logger, "Down")
		case <-time.After(10 * time.Second):
			finalClientConn.Close()
			wg.Done()
		}
	}()
	wg.Wait()
	// closes for all the things are deferred
	return
}
