package prefix

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/curve25519"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/refraction-networking/conjure/application/transports"
	"github.com/refraction-networking/conjure/application/transports/wrapping/internal/tests"
	"github.com/refraction-networking/conjure/pkg/core"
	"github.com/refraction-networking/gotapdance/ed25519"
	"github.com/refraction-networking/gotapdance/ed25519/extra25519"
	pb "github.com/refraction-networking/gotapdance/protobuf"
)

func TestSuccessfulWrap(t *testing.T) {
	testSubnetPath := os.Getenv("GOPATH") + "/src/github.com/refraction-networking/conjure/application/lib/test/phantom_subnets.toml"
	os.Setenv("PHANTOM_SUBNET_LOCATION", testSubnetPath)

	_, private, _ := ed25519.GenerateKey(rand.Reader)

	var curve25519Public, curve25519Private [32]byte
	extra25519.PrivateKeyToCurve25519(&curve25519Private, private)
	curve25519.ScalarBaseMult(&curve25519Public, &curve25519Private)

	var transport = Transport{
		TagObfuscator:     transports.CTRObfuscator{},
		Privkey:           curve25519Private,
		SupportedPrefixes: defaultPrefixes,
	}
	manager := tests.SetupRegistrationManager(tests.Transport{Index: pb.TransportType_Prefix, Transport: transport})
	c2p, sfp, reg := tests.SetupPhantomConnections(manager, pb.TransportType_Prefix, randomizeDstPortMinVersion)
	defer c2p.Close()
	defer sfp.Close()
	require.NotNil(t, reg)

	hmacID := core.ConjureHMAC(reg.Keys.SharedSecret, "PrefixTransportHMACString")
	message := []byte(`test message!`)

	for _, prefix := range defaultPrefixes {
		// if prefix.fn != nil {
		// 	// skip prefixes that do a special decoding for this test
		// 	continue
		// }

		obfuscatedID, err := transport.TagObfuscator.Obfuscate(hmacID, curve25519Public[:])
		require.Nil(t, err)
		// t.Logf("hmacid - %s\nobfuscated id - %s", hex.EncodeToString(hmacID), hex.EncodeToString(obfuscatedID))
		_, err = c2p.Write(append(prefix.StaticMatch, append(obfuscatedID, message...)...))
		require.Nil(t, err)

		var buf [4096]byte
		var buffer bytes.Buffer
		n, _ := sfp.Read(buf[:])
		buffer.Write(buf[:n])

		_, wrapped, err := transport.WrapConnection(&buffer, sfp, reg.PhantomIp, manager)
		require.Nil(t, err, "error getting wrapped connection")

		received := make([]byte, len(message))
		_, err = io.ReadFull(wrapped, received)
		require.Nil(t, err, "failed reading from connection")
		require.True(t, bytes.Equal(message, received), "%s\n%s\n%s", string(message), string(received), prefix.StaticMatch)
	}
}

func TestUnsuccessfulWrap(t *testing.T) {
	var transport = Transport{
		TagObfuscator:     transports.CTRObfuscator{},
		Privkey:           [32]byte{},
		SupportedPrefixes: defaultPrefixes,
	}

	manager := tests.SetupRegistrationManager(tests.Transport{Index: pb.TransportType_Prefix, Transport: transport})
	c2p, sfp, reg := tests.SetupPhantomConnections(manager, pb.TransportType_Prefix, randomizeDstPortMinVersion)
	defer c2p.Close()
	defer sfp.Close()

	// Write enough bytes that it can tell the message is definitively not associated with any prefix
	randMsg := make([]byte, 100)
	n, _ := rand.Read(randMsg)
	_, err := c2p.Write(randMsg[:n])
	require.Nil(t, err)

	var buf [1500]byte
	var buffer bytes.Buffer
	n, _ = sfp.Read(buf[:])

	buffer.Write(buf[:n])

	_, _, err = transport.WrapConnection(&buffer, sfp, reg.PhantomIp, manager)
	if !errors.Is(err, transports.ErrNotTransport) {
		t.Fatalf("expected ErrNotTransport, got %v", err)
	}
}

func TestTryAgain(t *testing.T) {
	var transport = Transport{
		TagObfuscator:     transports.CTRObfuscator{},
		Privkey:           [32]byte{},
		SupportedPrefixes: defaultPrefixes,
	}
	var err error
	manager := tests.SetupRegistrationManager(tests.Transport{Index: pb.TransportType_Prefix, Transport: transport})
	c2p, sfp, reg := tests.SetupPhantomConnections(manager, pb.TransportType_Prefix, randomizeDstPortMinVersion)
	defer c2p.Close()
	defer sfp.Close()

	msgBuf := make([]byte, 100)
	// Start out matching an expected prefix
	// Should match Min prefix until 64 bytes and GET prefix until 64+16 bytes
	copy(msgBuf[:], []byte("GET / HTTP/1.1\r\n"))

	var buf [100]byte
	var buffer bytes.Buffer
	for _, b := range msgBuf[:minTagLength+16-1] {
		_, err = c2p.Write([]byte{b})
		require.Nil(t, err)

		n, _ := sfp.Read(buf[:])
		buffer.Write(buf[:n])

		_, _, err = transport.WrapConnection(&buffer, sfp, reg.PhantomIp, manager)
		if !errors.Is(err, transports.ErrTryAgain) {
			t.Fatalf("expected ErrTryAgain, got %v", err)
		}
	}

	_, err = c2p.Write(msgBuf[minTagLength+16-1:])
	require.Nil(t, err)

	n, _ := sfp.Read(buf[:])
	buffer.Write(buf[:n])
	_, _, err = transport.WrapConnection(&buffer, sfp, reg.PhantomIp, manager)
	if !errors.Is(err, transports.ErrNotTransport) {
		t.Fatalf("expected ErrNotTransport, got %v", err)
	}
}

func TestTryParamsToDstPort(t *testing.T) {
	clv := randomizeDstPortMinVersion
	seed, _ := hex.DecodeString("0000000000000000000000000000000000")

	cases := []struct {
		r bool
		p uint16
	}{{true, 58047}, {false, 443}}

	transport, err := Default([32]byte{})
	require.Nil(t, err)

	// for id, _ := range transport.SupportedPrefixes {
	// 	t.Log(id.Name())
	// }

	for _, testCase := range cases {
		ct := ClientTransport{Parameters: &pb.PrefixTransportParams{RandomizeDstPort: &testCase.r}}

		rawParams, err := anypb.New(ct.GetParams())
		require.Nil(t, err)

		params, err := transport.ParseParams(clv, rawParams)
		require.Nil(t, err)

		port, err := transport.GetDstPort(clv, seed, params)
		require.Nil(t, err)
		require.Equal(t, testCase.p, port)
	}
}

func TestTryParseParamsBadPrefixID(t *testing.T) {
	clv := randomizeDstPortMinVersion

	// Dont Add anything to supported Transports
	transport, err := New([32]byte{})
	require.Nil(t, err)

	ct := ClientTransport{Parameters: &pb.PrefixTransportParams{}}

	rawParams, err := anypb.New(ct.GetParams())
	require.Nil(t, err)

	// Any transport Id will be unknown
	_, err = transport.ParseParams(clv, rawParams)
	require.ErrorIs(t, err, ErrUnknownPrefix)
}

/*
func TestSuccessfulWrapBase64(t *testing.T) {
	testSubnetPath := os.Getenv("GOPATH") + "/src/github.com/refraction-networking/conjure/application/lib/test/phantom_subnets.toml"
	os.Setenv("PHANTOM_SUBNET_LOCATION", testSubnetPath)

	_, private, _ := ed25519.GenerateKey(rand.Reader)

	var curve25519Public, curve25519Private [32]byte
	extra25519.PrivateKeyToCurve25519(&curve25519Private, private)
	curve25519.ScalarBaseMult(&curve25519Public, &curve25519Private)

	var transport = Transport{
		TagObfuscator:     transports.CTRObfuscator{},
		Privkey:           curve25519Private,
		SupportedPrefixes: defaultPrefixes,
	}
	manager := tests.SetupRegistrationManager(tests.Transport{Index: pb.TransportType_Prefix, Transport: transport})
	c2p, sfp, reg := tests.SetupPhantomConnections(manager, pb.TransportType_Prefix)
	defer c2p.Close()
	defer sfp.Close()
	require.NotNil(t, reg)

	hmacID := reg.Keys.ConjureHMAC("PrefixTransportHMACString")
	message := []byte(`test message!`)

	prefix := defaultPrefixes[0]

	obfuscatedID, err := transport.TagObfuscator.Obfuscate(hmacID, curve25519Public[:])
	require.Nil(t, err)

	encodedID := base64.StdEncoding.EncodeToString(obfuscatedID)

	decodedID, _, err := prefix.fn([]byte(encodedID))
	require.Nil(t, err)
	require.True(t, bytes.Equal(decodedID, obfuscatedID))

	_, err = c2p.Write(append(prefix.StaticMatch, append([]byte(encodedID), message...)...))
	require.Nil(t, err)

	var buf [4096]byte
	var buffer bytes.Buffer
	n, _ := sfp.Read(buf[:])
	buffer.Write(buf[:n])

	_, wrapped, err := transport.WrapConnection(&buffer, sfp, reg.PhantomIp, manager)
	require.Nil(t, err, "error getting wrapped connection")

	received := make([]byte, len(message))
	_, err = io.ReadFull(wrapped, received)
	require.Nil(t, err, "failed reading from connection")
	require.True(t, bytes.Equal(message, received), "%s\n%s\n%s", string(message), string(received), prefix.StaticMatch)

}
*/
