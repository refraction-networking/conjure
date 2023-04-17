package utls

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"io"
	"net/http"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/anypb"

	cj "github.com/refraction-networking/conjure/application/lib"
	"github.com/refraction-networking/conjure/application/transports"
	"github.com/refraction-networking/conjure/application/transports/wrapping/internal/tests"
	pb "github.com/refraction-networking/gotapdance/protobuf"
	tls "github.com/refraction-networking/utls"
)

func formatClientPacket(reg *cj.DecoyRegistration, params any) ([]byte, error) {

	// TODO: put these in params
	helloID := tls.HelloChrome_102
	config := tls.Config{ServerName: "", InsecureSkipVerify: true}

	uTLSConn := tls.UClient(nil, &config, helloID)
	hmacID := reg.Keys.ConjureHMAC(hmacString)

	err := uTLSConn.BuildHandshakeState() // Apply our client hello ID
	if err != nil {
		return nil, err
	}
	uTLSConn.SetClientRandom(hmacID)
	err = uTLSConn.MarshalClientHello() // apply the updated ch random value
	if err != nil {
		return nil, err
	}

	return uTLSConn.HandshakeState.Hello.Marshal()
}

func DisabledTestMarshalRandom(t *testing.T) {
	hmacID := make([]byte, 32)
	_, err := rand.Read(hmacID)
	require.Nil(t, err)

	helloID := tls.HelloChrome_102
	config := tls.Config{ServerName: "", InsecureSkipVerify: true}

	uTLSConn := tls.UClient(nil, &config, helloID)

	err = uTLSConn.BuildHandshakeState()
	require.Nil(t, err)
	uTLSConn.SetClientRandom(hmacID)

	err = uTLSConn.BuildHandshakeState()
	require.Nil(t, err)

	// t.Log(hex.EncodeToString(hmacID))
	// t.Log(hex.EncodeToString(uTLSConn.HandshakeState.Hello.Random))

	b, err := uTLSConn.HandshakeState.Hello.Marshal()
	require.Nil(t, err)

	ch := tls.UnmarshalClientHello(b)
	require.NotNil(t, ch)
	// t.Log(hex.EncodeToString(ch.Random))
	require.True(t, bytes.Equal(ch.Random, hmacID))
}

func DisabledTestMarshalSNI(t *testing.T) {
	hmacID := [32]byte{}
	_, err := rand.Read(hmacID[:])
	require.Nil(t, err)

	helloID := tls.HelloChrome_102
	config := tls.Config{ServerName: hex.EncodeToString(hmacID[:]), InsecureSkipVerify: true}

	uTLSConn := tls.UClient(nil, &config, helloID)

	err = uTLSConn.BuildHandshakeState()
	require.Nil(t, err)

	b, err := uTLSConn.HandshakeState.Hello.Marshal()
	require.Nil(t, err)

	ch := tls.UnmarshalClientHello(b)
	require.NotNil(t, ch)

	recv, err := hex.DecodeString(ch.ServerName)
	require.Nil(t, err)
	require.True(t, bytes.Equal(recv, hmacID[:]))
}

func TestSuccessfulWrap(t *testing.T) {
	testSubnetPath := os.Getenv("GOPATH") + "/src/github.com/refraction-networking/conjure/application/lib/test/phantom_subnets.toml"
	os.Setenv("PHANTOM_SUBNET_LOCATION", testSubnetPath)

	var transport Transport
	manager := tests.SetupRegistrationManager(tests.Transport{Index: pb.TransportType_Prefix, Transport: transport})
	c2p, sfp, reg := tests.SetupPhantomConnections(manager, pb.TransportType_Prefix)
	defer c2p.Close()
	defer sfp.Close()
	require.NotNil(t, reg)

	message := []byte(`test message!`)

	connectMsg, err := formatClientPacket(reg, nil)
	require.Nil(t, err)
	_, err = c2p.Write(connectMsg)
	require.Nil(t, err)

	var buf [4096]byte
	n, _ := sfp.Read(buf[:])

	_, wrapped, err := transport.WrapConnection(bytes.NewBuffer(buf[:n]), sfp, reg.PhantomIp, manager)
	require.Nil(t, err, "error getting wrapped connection")

	_, err = c2p.Write(message)
	require.Nil(t, err)

	received := make([]byte, len(message))
	_, err = io.ReadFull(wrapped, received)
	require.Nil(t, err, "failed reading from connection")
	require.True(t, bytes.Equal(message, received))
}

func TestUnsuccessfulWrap(t *testing.T) {
	var transport Transport
	manager := tests.SetupRegistrationManager(tests.Transport{Index: pb.TransportType_Prefix, Transport: transport})
	c2p, sfp, reg := tests.SetupPhantomConnections(manager, pb.TransportType_Prefix)
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
	c2p, sfp, reg := tests.SetupPhantomConnections(manager, pb.TransportType_Prefix)
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
	testSubnetPath := os.Getenv("GOPATH") + "/src/github.com/refraction-networking/conjure/application/lib/test/phantom_subnets.toml"
	os.Setenv("PHANTOM_SUBNET_LOCATION", testSubnetPath)

	var transport Transport
	manager := tests.SetupRegistrationManager(tests.Transport{Index: pb.TransportType_Prefix, Transport: transport})
	c2p, sfp, reg := tests.SetupPhantomConnections(manager, pb.TransportType_Prefix)
	defer c2p.Close()
	defer sfp.Close()
	require.NotNil(t, reg)

	connectMsg, err := formatClientPacket(reg, nil)
	require.Nil(t, err)
	_, err = c2p.Write(connectMsg)
	require.Nil(t, err)

	var buf [4096]byte
	var buffer bytes.Buffer
	n, _ := sfp.Read(buf[:])
	buffer.Write(buf[:n])

	_, wrapped, err := transport.WrapConnection(&buffer, sfp, reg.PhantomIp, manager)
	require.Nil(t, err, "error getting wrapped connection")

	message := make([]byte, 10000)
	_, err = rand.Read(message)
	require.Nil(t, err)

	_, err = c2p.Write(message)
	require.Nil(t, err)

	received := make([]byte, len(message))
	n, err = io.ReadFull(wrapped, received)
	require.Nil(t, err, "failed reading from connection")
	require.True(t, bytes.Equal(message[:n], received), "xptd: %s\nrecv: %s", hex.EncodeToString(message[:len(received)]), hex.EncodeToString(received))
	// t.Log("l:", n)
}

func TestTryParamsToDstPort(t *testing.T) {
	clv := randomizeDstPortMinVersion
	seed, _ := hex.DecodeString("0000000000000000000000000000000000")

	cases := []struct {
		r bool
		p uint16
	}{{true, 58047}, {false, defaultPort}}

	for _, testCase := range cases {
		ct := ClientTransport{Parameters: &pb.GenericTransportParams{RandomizeDstPort: &testCase.r}}
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
