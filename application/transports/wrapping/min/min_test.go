package min

import (
	"bytes"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/refraction-networking/conjure/application/transports"
	"github.com/refraction-networking/conjure/application/transports/wrapping/internal/tests"
	pb "github.com/refraction-networking/gotapdance/protobuf"
)

func TestSuccessfulWrap(t *testing.T) {
	testSubnetPath := os.Getenv("GOPATH") + "/src/github.com/refraction-networking/conjure/application/lib/test/phantom_subnets.toml"
	os.Setenv("PHANTOM_SUBNET_LOCATION", testSubnetPath)

	var transport Transport
	manager := tests.SetupRegistrationManager(tests.Transport{Index: pb.TransportType_Min, Transport: transport})
	c2p, sfp, reg := tests.SetupPhantomConnections(manager, pb.TransportType_Min)
	defer c2p.Close()
	defer sfp.Close()
	require.NotNil(t, reg)

	hmacID := reg.Keys.ConjureHMAC("MinTrasportHMACString")
	message := []byte(`test message!`)

	_, err := c2p.Write(append(hmacID, message...))
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
	require.True(t, bytes.Equal(message, received))
}

func TestUnsuccessfulWrap(t *testing.T) {
	var transport Transport
	manager := tests.SetupRegistrationManager(tests.Transport{Index: pb.TransportType_Min, Transport: transport})
	c2p, sfp, reg := tests.SetupPhantomConnections(manager, pb.TransportType_Min)
	defer c2p.Close()
	defer sfp.Close()

	// No real reason for sending the shared secret; it's just 32 bytes
	// (same length as HMAC ID) that should have no significance.
	_, err := c2p.Write(tests.SharedSecret)
	require.Nil(t, err)

	var buf [32]byte
	var buffer bytes.Buffer
	n, _ := sfp.Read(buf[:])
	buffer.Write(buf[:n])

	_, _, err = transport.WrapConnection(&buffer, sfp, reg.PhantomIp, manager)
	if !errors.Is(err, transports.ErrNotTransport) {
		t.Fatalf("expected ErrNotTransport, got %v", err)
	}
}

func TestTryAgain(t *testing.T) {
	var transport Transport
	var err error
	manager := tests.SetupRegistrationManager(tests.Transport{Index: pb.TransportType_Min, Transport: transport})
	c2p, sfp, reg := tests.SetupPhantomConnections(manager, pb.TransportType_Min)
	defer c2p.Close()
	defer sfp.Close()

	var buf [32]byte
	var buffer bytes.Buffer
	for _, b := range tests.SharedSecret[:31] {
		_, err = c2p.Write([]byte{b})
		require.Nil(t, err)

		n, _ := sfp.Read(buf[:])
		buffer.Write(buf[:n])

		_, _, err = transport.WrapConnection(&buffer, sfp, reg.PhantomIp, manager)
		if !errors.Is(err, transports.ErrTryAgain) {
			t.Fatalf("expected ErrTryAgain, got %v", err)
		}
	}

	_, err = c2p.Write(tests.SharedSecret[31:])
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

	cases := []struct{
		r bool
		p uint16
	}{{true, 58047}, {false, 443}}

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
