package min

import (
	"bytes"
	"errors"
	"io"
	"os"
	"testing"

	"github.com/stretchr/testify/require"

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

	hmacID := reg.Keys.ConjureHMAC("MinTrasportHMACString")
	message := []byte(`test message!`)

	_, err := c2p.Write(append(hmacID, message...))
	require.Nil(t, err)

	var buf [4096]byte
	var buffer bytes.Buffer
	n, _ := sfp.Read(buf[:])
	buffer.Write(buf[:n])

	_, wrapped, err := transport.WrapConnection(&buffer, sfp, reg.DarkDecoy, manager)
	if err != nil {
		t.Fatalf("expected nil, got %v", err)
	}

	received := make([]byte, len(message))
	_, err = io.ReadFull(wrapped, received)
	if err != nil {
		t.Fatalf("failed reading from connection: %v", err)
	}

	if !bytes.Equal(message, received) {
		t.Fatalf("expected %v, got %v", message, received)
	}
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

	_, _, err = transport.WrapConnection(&buffer, sfp, reg.DarkDecoy, manager)
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

		_, _, err = transport.WrapConnection(&buffer, sfp, reg.DarkDecoy, manager)
		if !errors.Is(err, transports.ErrTryAgain) {
			t.Fatalf("expected ErrTryAgain, got %v", err)
		}
	}

	_, err = c2p.Write(tests.SharedSecret[31:])
	require.Nil(t, err)

	n, _ := sfp.Read(buf[:])
	buffer.Write(buf[:n])
	_, _, err = transport.WrapConnection(&buffer, sfp, reg.DarkDecoy, manager)
	if !errors.Is(err, transports.ErrNotTransport) {
		t.Fatalf("expected ErrNotTransport, got %v", err)
	}
}
