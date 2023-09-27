package utls

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/refraction-networking/conjure/internal/conjurepath"
	"github.com/refraction-networking/conjure/pkg/core"
	cj "github.com/refraction-networking/conjure/pkg/station/lib"
	"github.com/refraction-networking/conjure/pkg/transports"
	pb "github.com/refraction-networking/conjure/proto"
	tls "github.com/refraction-networking/utls"
)

var testSubnetPath = conjurepath.Root + "/internal/test_assets/phantom_subnets.toml"

func connect(conn net.Conn, reg *cj.DecoyRegistration) (net.Conn, error) {
	// TODO: put these in params
	helloID := tls.HelloChrome_62
	config := tls.Config{ServerName: "", InsecureSkipVerify: true}

	uTLSConn := tls.UClient(conn, &config, helloID)
	hmacID := core.ConjureHMAC(reg.Keys.SharedSecret, hmacString)

	newRand := make([]byte, 32)
	_, err := rand.Read(newRand)
	if err != nil {
		return nil, err
	}

	err = uTLSConn.BuildHandshakeState() // Apply our client hello ID
	if err != nil {
		return nil, err
	}
	uTLSConn.SetClientRandom(newRand)
	// fmt.Printf("clientRandom set - handshaking %s\n", hex.EncodeToString(hmacID))

	uTLSConn.HandshakeState.Hello.SessionId = xorBytes(hmacID, newRand)

	err = uTLSConn.MarshalClientHello() // apply the updated ch random value
	if err != nil {
		return nil, err
	}

	return uTLSConn, uTLSConn.Handshake()
}

func TestByteRegex(t *testing.T) {
	testCases := []struct {
		s string
		l uint16
	}{
		{s: "16030100e2000000", l: 226},
		{s: "160301ff00000000", l: 65280},
	}

	badCases := []string{
		"15030100e2000000",
		"160301ff",
		"0016030100e2000000",
	}

	for _, c := range testCases {
		b, err := hex.DecodeString(c.s)
		require.Nil(t, err)

		out := tlsHeaderRegex.FindSubmatch(b)
		// for _, x := range out {
		// 	t.Logf("%s", hex.EncodeToString(x))
		// }
		require.Equal(t, 2, len(out))
		require.Equal(t, 2, len(out[1]))
		u := binary.BigEndian.Uint16(out[1])
		require.Equal(t, c.l, u)
	}
	for _, c := range badCases {
		b, err := hex.DecodeString(c)
		require.Nil(t, err)

		out := tlsHeaderRegex.FindSubmatch(b)
		require.Equal(t, 0, len(out))
	}
}

func TestSuccessfulWrap(t *testing.T) {
	os.Setenv("PHANTOM_SUBNET_LOCATION", testSubnetPath)

	var transport Transport
	manager := tests.SetupRegistrationManager(tests.Transport{Index: pb.TransportType_Prefix, Transport: transport})
	c2p, sfp, reg := tests.SetupPhantomConnections(manager, pb.TransportType_Prefix, nil, randomizeDstPortMinVersion)
	defer c2p.Close()
	defer sfp.Close()
	require.NotNil(t, reg)

	message := []byte(`test message!`)

	go func() {
		var buf [1501]byte

		var wrapped net.Conn
		var err error
		for {
			n, err := sfp.Read(buf[:])
			if err != nil {
				panic("station read error")
			}

			reg, wrapped, err = transport.WrapConnection(bytes.NewBuffer(buf[:n]), sfp, reg.PhantomIp, manager)
			if errors.Is(err, transports.ErrNotTransport) {
				panic("failed to find registration")
			} else if errors.Is(err, transports.ErrTransportNotSupported) {
				panic("transport supposed to be supported but isn't")
			} else if err == nil {
				break
			} // on transports.ErrTryAgain it should continue loop.
		}

		stationReceived := make([]byte, len(message))
		_, err = io.ReadFull(wrapped, stationReceived)
		if err != nil {
			panic(fmt.Sprintf("failed ReadFull: %s %s", stationReceived, err))
		}
		_, err = wrapped.Write(stationReceived)
		if err != nil {
			panic("failed Write")
		}
	}()

	clientConn, err := connect(c2p, reg)
	require.Nil(t, err)

	_, err = clientConn.Write(message)
	require.Nil(t, err)

	received := make([]byte, len(message))
	_, err = io.ReadFull(clientConn, received)
	require.Nil(t, err, "failed reading from connection")
	require.True(t, bytes.Equal(message, received))
}

func TestUnsuccessfulWrap(t *testing.T) {
	var transport Transport
	manager := tests.SetupRegistrationManager(tests.Transport{Index: pb.TransportType_Prefix, Transport: transport})
	c2p, sfp, reg := tests.SetupPhantomConnections(manager, pb.TransportType_Prefix, nil, randomizeDstPortMinVersion)
	defer c2p.Close()
	defer sfp.Close()

	message := []byte(`test message!`)

	// No real reason for sending the shared secret; it's just 32 bytes
	// (same length as HMAC ID) that should have no significance.
	req, err := http.NewRequest(http.MethodGet, "/", bytes.NewReader(message))
	require.Nil(t, err)
	req.Header.Add("X-Ignore", base64.StdEncoding.EncodeToString(tests.SharedSecret))
	err = req.Write(c2p)
	require.Nil(t, err)

	var buf [128]byte
	var buffer bytes.Buffer
	n, _ := sfp.Read(buf[:])
	buffer.Write(buf[:n])

	_, _, err = transport.WrapConnection(&buffer, sfp, reg.PhantomIp, manager)
	require.ErrorIs(t, err, transports.ErrNotTransport)
}

func TestTryAgain(t *testing.T) {
	var transport Transport
	var err error
	manager := tests.SetupRegistrationManager(tests.Transport{Index: pb.TransportType_Prefix, Transport: transport})
	c2p, sfp, reg := tests.SetupPhantomConnections(manager, pb.TransportType_Prefix, nil, randomizeDstPortMinVersion)
	defer c2p.Close()
	defer sfp.Close()

	var buffer bytes.Buffer

	// The only way that we should be able to get ErrTryAgain is if it was
	// called on a read with 0 bytes
	_, _, err = transport.WrapConnection(&buffer, sfp, reg.PhantomIp, manager)
	require.ErrorIs(t, err, transports.ErrTryAgain)
	message := []byte(`test message!`)

	// No real reason for sending the shared secret; it's just 32 bytes
	// (same length as HMAC ID) that should have no significance.
	req, err := http.NewRequest(http.MethodGet, "/", bytes.NewReader(message))
	require.Nil(t, err)
	req.Header.Add("X-Ignore", base64.StdEncoding.EncodeToString(tests.SharedSecret))
	err = req.Write(c2p)
	require.Nil(t, err)

	var buf [128]byte
	n, _ := sfp.Read(buf[:])
	buffer.Write(buf[:n])

	_, _, err = transport.WrapConnection(&buffer, sfp, reg.PhantomIp, manager)
	require.ErrorIs(t, err, transports.ErrNotTransport)
}

func TestSuccessfulWrapLargeMessage(t *testing.T) {
	os.Setenv("PHANTOM_SUBNET_LOCATION", testSubnetPath)

	var transport Transport
	manager := tests.SetupRegistrationManager(tests.Transport{Index: pb.TransportType_Prefix, Transport: transport})
	c2p, sfp, reg := tests.SetupPhantomConnections(manager, pb.TransportType_Prefix, nil, randomizeDstPortMinVersion)
	defer c2p.Close()
	defer sfp.Close()
	require.NotNil(t, reg)

	message := make([]byte, 10000)
	_, err := rand.Read(message)
	require.Nil(t, err)

	go func() {
		var buf [1501]byte

		var wrapped net.Conn
		var err error
		for {
			n, err := sfp.Read(buf[:])
			if err != nil {
				panic("station read error")
			}

			reg, wrapped, err = transport.WrapConnection(bytes.NewBuffer(buf[:n]), sfp, reg.PhantomIp, manager)
			if errors.Is(err, transports.ErrNotTransport) {
				panic("failed to find registration")
			} else if errors.Is(err, transports.ErrTransportNotSupported) {
				panic("transport supposed to be supported but isn't")
			} else if err == nil {
				break
			} // on transports.ErrTryAgain it should continue loop.
		}

		stationReceived := make([]byte, len(message))
		_, err = io.ReadFull(wrapped, stationReceived)
		if err != nil {
			panic(fmt.Sprintf("failed ReadFull: %s %s", stationReceived, err))
		}
		_, err = wrapped.Write(stationReceived)
		if err != nil {
			panic("failed Write")
		}
	}()

	clientConn, err := connect(c2p, reg)
	require.Nil(t, err)

	_, err = clientConn.Write(message)
	require.Nil(t, err)

	received := make([]byte, len(message))
	n, err := io.ReadFull(clientConn, received)
	require.Nil(t, err, "failed reading from connection")
	require.True(t, bytes.Equal(message[:n], received))
}

func TestTryParamsToDstPort(t *testing.T) {
	clv := randomizeDstPortMinVersion
	seed, _ := hex.DecodeString("0000000000000000000000000000000000")

	cases := []struct {
		r bool
		p uint16
	}{{true, 58047}, {false, defaultPort}}

	for _, testCase := range cases {
		ct := ClientTransport{Parameters: &pb.UTLSTransportParams{RandomizeDstPort: &testCase.r}}
		var transport Transport

		rawParams, err := anypb.New(ct.GetParams())
		require.Nil(t, err)

		params, err := transport.ParseParams(clv, rawParams)
		require.Nil(t, err)

		port, err := transport.GetDstPort(clv, seed, params)
		require.Nil(t, err)
		require.Equal(t, testCase.p, port)
	}
}

func TestUtlsSessionResumption(t *testing.T) {
	var err error
	c2p, sfp := net.Pipe()

	message := []byte(`test message!`)

	randVal := [32]byte{}
	n, err := rand.Read(randVal[:])
	require.Nil(t, err)
	require.Equal(t, 32, n)
	domainName := "abc.def.com"

	cert, err := newCertificate(randVal[:])
	serverConfig := &tls.Config{
		Certificates:           []tls.Certificate{*cert},
		MinVersion:             tls.VersionTLS10,
		MaxVersion:             tls.VersionTLS12,
		SessionTicketsDisabled: false,
		ClientAuth:             tls.RequireAnyClientCert,
		VerifyConnection:       buildSymmetricVerifier(randVal[:]),
		CipherSuites:           []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
	}

	go func() {
		config := *serverConfig

		config.BuildNameToCertificate()
		config.SetSessionTicketKeys([][32]byte{randVal})

		wrapped := tls.Server(sfp, &config)

		stationReceived := make([]byte, len(message))
		_, err := io.ReadFull(wrapped, stationReceived)
		if err != nil {
			t.Logf("failed ReadFull: %s %s", stationReceived, err)
			t.Logf("%v", config.CipherSuites)
			t.Fail()
			return
		}
		_, err = wrapped.Write(stationReceived)
		if err != nil {
			t.Logf("failed Write")
			t.Fail()
			return
		}
	}()

	serverSession, err := tls.ForgeServerSessionState(randVal[:], serverConfig, tls.HelloChrome_Auto)

	sessionTicket, err := serverSession.MakeEncryptedTicket(randVal, &tls.Config{})

	// Create a session ticket that wasn't actually issued by the server.
	sessionState := tls.MakeClientSessionState(sessionTicket, uint16(tls.VersionTLS12),
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		randVal[:],
		nil, nil)

	config := &tls.Config{
		ServerName:   domainName,
		Certificates: []tls.Certificate{*cert},
		// VerifyConnection: buildSymmetricVerifier(randVal[:]),
	}
	clientTLSConn := tls.UClient(c2p, config, tls.HelloGolang)
	require.NotNil(t, clientTLSConn)

	err = clientTLSConn.BuildHandshakeState()
	require.Nil(t, err)

	// SetSessionState sets the session ticket, which may be preshared or fake.
	err = clientTLSConn.SetSessionState(sessionState)
	require.Nil(t, err)

	_, err = clientTLSConn.Write(message)
	require.Nil(t, err)

	received := make([]byte, len(message))
	_, err = io.ReadFull(clientTLSConn, received)
	require.Nil(t, err, "failed reading from connection")
	require.True(t, bytes.Equal(message, received))
}

func TestUtlsSessionResumptionTCP(t *testing.T) {
	var err error
	listenAddr := &net.TCPAddr{
		IP:   net.IPv6loopback,
		Port: 4443,
	}
	message := []byte(`test message!`)

	randVal := [32]byte{}
	n, err := rand.Read(randVal[:])
	require.Nil(t, err)
	require.Equal(t, 32, n)
	domainName := "abc.def.com"
	ordering := make(chan struct{})
	cert, err := newCertificate(randVal[:])
	serverConfig := &tls.Config{
		Certificates:           []tls.Certificate{*cert},
		MinVersion:             tls.VersionTLS10,
		MaxVersion:             tls.VersionTLS12,
		SessionTicketsDisabled: false,
		ClientAuth:             tls.RequireAnyClientCert,
		VerifyConnection:       buildSymmetricVerifier(randVal[:]),
		CipherSuites:           []uint16{tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256},
	}

	go func() {
		config := *serverConfig

		config.BuildNameToCertificate()
		config.SetSessionTicketKeys([][32]byte{randVal})

		l, err := net.ListenTCP("tcp", listenAddr)
		if err != nil {
			t.Fail()
			ordering <- struct{}{}
			return
		}
		defer l.Close()

		ordering <- struct{}{}

		sfc, err := l.Accept()
		if err != nil {
			t.Fail()
			return
		}

		wrapped := tls.Server(sfc, &config)

		stationReceived := make([]byte, len(message))
		_, err = io.ReadFull(wrapped, stationReceived)
		if err != nil {
			t.Logf("failed ReadFull: %s %s", stationReceived, err)
			t.Logf("%v", config.CipherSuites)
			t.Fail()
			return
		}
		_, err = wrapped.Write(stationReceived)
		if err != nil {
			t.Logf("failed Write")
			t.Fail()
			return
		}
	}()

	serverSession, err := tls.ForgeServerSessionState(randVal[:], serverConfig, tls.HelloChrome_Auto)
	require.Nil(t, err)

	sessionTicket, err := serverSession.MakeEncryptedTicket(randVal, &tls.Config{})
	require.Nil(t, err)

	// Create a session ticket that wasn't actually issued by the server.
	sessionState := tls.MakeClientSessionState(sessionTicket, uint16(tls.VersionTLS12),
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
		randVal[:],
		nil, nil)

	config := &tls.Config{
		ServerName:   domainName,
		Certificates: []tls.Certificate{*cert},
		// VerifyConnection: buildSymmetricVerifier(randVal[:]),
	}

	<-ordering
	c2p, err := net.Dial("tcp", listenAddr.String())
	require.Nil(t, err)

	clientTLSConn := tls.UClient(c2p, config, tls.HelloGolang)
	require.NotNil(t, clientTLSConn)

	err = clientTLSConn.BuildHandshakeState()
	require.Nil(t, err)

	// SetSessionState sets the session ticket, which may be preshared or fake.
	err = clientTLSConn.SetSessionState(sessionState)
	require.Nil(t, err)

	_, err = clientTLSConn.Write(message)
	require.Nil(t, err)

	received := make([]byte, len(message))
	_, err = io.ReadFull(clientTLSConn, received)
	require.Nil(t, err, "failed reading from connection")
	require.True(t, bytes.Equal(message, received))
}

const (
	// ticketKeyNameLen is the number of bytes of identifier that is prepended to
	// an encrypted session ticket in order to identify the key used to encrypt it.
	ticketKeyNameLen = 16
)

// // returns the session state and the marshalled sessionTicket, or an error should one occur.
// func forgeSession(secret [32]byte, chID tls.ClientHelloID, r io.Reader) (*tls.ClientSessionState, []byte, error) {
// 	key := tls.TicketKeyFromBytes(secret)
// 	serverState, err := tls.ForgeServerSessionState(secret[:], chID)
// 	if err != nil {
// 		return nil, nil, err
// 	}
// 	stateBytes, err := serverState.Marshal()
// 	if err != nil {
// 		return nil, nil, err
// 	}

// 	encrypted := make([]byte, ticketKeyNameLen+aes.BlockSize+len(stateBytes)+sha256.Size)
// 	keyName := encrypted[:ticketKeyNameLen]
// 	iv := encrypted[ticketKeyNameLen : ticketKeyNameLen+aes.BlockSize]
// 	macBytes := encrypted[len(encrypted)-sha256.Size:]

// 	if _, err := io.ReadFull(r, iv); err != nil {
// 		return nil, nil, err
// 	}

// 	copy(keyName, key.KeyName[:])
// 	block, err := aes.NewCipher(key.AesKey[:])
// 	if err != nil {
// 		return nil, nil, errors.New("tls: failed to create cipher while encrypting ticket: " + err.Error())
// 	}
// 	cipher.NewCTR(block, iv).XORKeyStream(encrypted[ticketKeyNameLen+aes.BlockSize:], stateBytes)

// 	mac := hmac.New(sha256.New, key.HmacKey[:])
// 	mac.Write(encrypted[:len(encrypted)-sha256.Size])
// 	mac.Sum(macBytes[:0])

// 	state := tls.MakeClientSessionState(encrypted, uint16(tls.VersionTLS12),
// 		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
// 		secret[:],
// 		nil, nil)

// 	return state, encrypted, nil
// }

// https://github.com/refraction-networking/utls/blob/c785bd3a1e8dd394d36526a2f3f118a21fc002c5/handshake_server_tls13.go#L736
// https://github.com/refraction-networking/utls/blob/c785bd3a1e8dd394d36526a2f3f118a21fc002c5/handshake_server.go#L769
