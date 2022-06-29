package obfs4

import (
	"bytes"
	"errors"
	"io"
	"log"
	"math/rand"
	"net"
	"os"
	"testing"
	"time"

	dd "github.com/refraction-networking/conjure/application/lib"
	"github.com/refraction-networking/conjure/application/transports"
	"github.com/refraction-networking/conjure/application/transports/wrapping/internal/tests"
	pb "github.com/refraction-networking/gotapdance/protobuf"

	pt "git.torproject.org/pluggable-transports/goptlib.git"
	"github.com/stretchr/testify/require"
	"gitlab.com/yawning/obfs4.git/transports/obfs4"
)

func wrapConnection(conn net.Conn, nodeID, publicKey string, wrapped chan (net.Conn), stateDir string) {
	args := pt.Args{}
	args.Add("node-id", nodeID)
	args.Add("public-key", publicKey)
	args.Add("iat-mode", "1")

	t := obfs4.Transport{}
	c, err := t.ClientFactory(stateDir)
	if err != nil {
		log.Fatalln("failed to set up client factory:", err)
	}

	parsedArgs, err := c.ParseArgs(&args)
	if err != nil {
		log.Fatalln("failed to parse args:", err)
	}

	dial := func(string, string) (net.Conn, error) { return conn, nil }
	w, err := c.Dial("tcp", "", dial, parsedArgs)
	if err != nil {
		log.Fatalln("failed to wrap connection:", err)
	}

	wrapped <- w
}

func TestSuccessfulWrap(t *testing.T) {
	testSubnetPath := os.Getenv("GOPATH") + "/src/github.com/refraction-networking/conjure/application/lib/test/phantom_subnets.toml"
	os.Setenv("PHANTOM_SUBNET_LOCATION", testSubnetPath)

	var transport Transport
	manager := tests.SetupRegistrationManager(tests.Transport{Index: pb.TransportType_Obfs4, Transport: transport})
	c2p, sfp, reg := tests.SetupPhantomConnections(manager, pb.TransportType_Obfs4)
	defer c2p.Close()
	defer sfp.Close()

	wrappedc2p := make(chan net.Conn)
	stateDir := t.TempDir()
	go wrapConnection(c2p, reg.Keys.Obfs4Keys.NodeID.Hex(), reg.Keys.Obfs4Keys.PublicKey.Hex(), wrappedc2p, stateDir)

	var buf [4096]byte
	var buffer bytes.Buffer
	var wrappedsfp net.Conn
	var err error
	for {
		n, _ := sfp.Read(buf[:])
		buffer.Write(buf[:n])

		_, wrappedsfp, err = transport.WrapConnection(&buffer, sfp, reg.DarkDecoy, manager)
		if errors.Is(err, transports.ErrTryAgain) {
			continue
		} else if err != nil {
			t.Fatalf("expected nil or ErrTryAgain, got %v", err)
		}

		break
	}

	select {
	case c2p = <-wrappedc2p:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("timed out waiting for wrapped client connection")
	}

	message := []byte(`test message!`)
	_, err = c2p.Write(message)
	require.Nil(t, err)

	received := make([]byte, len(message))
	_, err = io.ReadFull(wrappedsfp, received)
	if err != nil {
		t.Fatalf("failed reading from connection: %v", err)
	}

	if !bytes.Equal(message, received) {
		t.Fatalf("expected %v, got %v", message, received)
	}
}

// TestSuccessfulWrapMulti is designed to ensure that the obfs4 implementation
// of WrapConnection works when multiple registrations might share the same
// phantom IP address. This requires mapping multiple registrations to the same
// phantom before calling WrapConnection on one of them. This is done using a
// subnet file that only has a an /32 allocation meaning all registrations by
// default map to the same phantom address (for n=5 registrations). We wrap the
// last connection.
func TestSuccessfulWrapMulti(t *testing.T) {
	testSubnetPath := os.Getenv("GOPATH") + "/src/github.com/refraction-networking/conjure/application/lib/test/phantom_subnets_min.toml"
	os.Setenv("PHANTOM_SUBNET_LOCATION", testSubnetPath)

	sharedSecrets := [][]byte{
		[]byte(`b07c17169ac6c4ec77de4b795e939e3994dc708be1afb6bcd5e646941cf97f35`),
		[]byte(`3143952b9355b6187ddc6104eb9ea85fca52ba5f8d88a93f73910f860b133217`),
		[]byte(`62a807d9f89673960564185e893530216ef889545d9c039f9b02d8ccd36c093d`),
		[]byte(`d078a5084786cfd51094e6c27718451e1260285068b6dbc7009c06de38d49711`),
		tests.SharedSecret,
	}

	var transport Transport
	manager := tests.SetupRegistrationManager(tests.Transport{Index: pb.TransportType_Obfs4, Transport: transport})
	var c2p, sfp net.Conn
	var reg *dd.DecoyRegistration

	// register 5 sessions guaranteeing collisions on phantom IP addresses
	for _, secret := range sharedSecrets {
		c2p, sfp, reg = tests.SetupPhantomConnectionsSecret(manager, pb.TransportType_Obfs4, secret, testSubnetPath)
	}

	defer c2p.Close()
	defer sfp.Close()

	wrappedc2p := make(chan net.Conn)
	stateDir := t.TempDir()
	go wrapConnection(c2p, reg.Keys.Obfs4Keys.NodeID.Hex(), reg.Keys.Obfs4Keys.PublicKey.Hex(), wrappedc2p, stateDir)

	var buf [4096]byte
	var buffer bytes.Buffer
	var wrappedsfp net.Conn
	var err error
	for {
		n, _ := sfp.Read(buf[:])
		buffer.Write(buf[:n])

		_, wrappedsfp, err = transport.WrapConnection(&buffer, sfp, reg.DarkDecoy, manager)
		if errors.Is(err, transports.ErrTryAgain) {
			continue
		} else if err != nil {
			t.Fatalf("expected nil or ErrTryAgain, got %v", err)
		}

		break
	}

	select {
	case c2p = <-wrappedc2p:
	case <-time.After(100 * time.Millisecond):
		t.Fatal("timed out waiting for wrapped client connection")
	}

	message := []byte(`test message!`)
	_, err = c2p.Write(message)
	require.Nil(t, err)

	received := make([]byte, len(message))
	_, err = io.ReadFull(wrappedsfp, received)
	if err != nil {
		t.Fatalf("failed reading from connection: %v", err)
	}

	if !bytes.Equal(message, received) {
		t.Fatalf("expected %v, got %v", message, received)
	}
}

func TestUnsuccessfulWrap(t *testing.T) {
	var transport Transport
	var err error
	manager := tests.SetupRegistrationManager(tests.Transport{Index: pb.TransportType_Obfs4, Transport: transport})
	c2p, sfp, reg := tests.SetupPhantomConnections(manager, pb.TransportType_Obfs4)
	defer c2p.Close()
	defer sfp.Close()

	_, err = io.Copy(c2p, io.LimitReader(rand.New(rand.NewSource(0)), 8192))
	require.Nil(t, err)

	var buf [8192]byte
	var buffer bytes.Buffer
	n, _ := io.ReadFull(sfp, buf[:])
	buffer.Write(buf[:n])

	_, _, err = transport.WrapConnection(&buffer, sfp, reg.DarkDecoy, manager)
	if !errors.Is(err, transports.ErrNotTransport) {
		t.Fatalf("expected ErrNotTransport, got %v", err)
	}
}

func TestTryAgain(t *testing.T) {
	var transport Transport
	var err error
	manager := tests.SetupRegistrationManager(tests.Transport{Index: pb.TransportType_Obfs4, Transport: transport})
	c2p, sfp, reg := tests.SetupPhantomConnections(manager, pb.TransportType_Obfs4)
	defer c2p.Close()
	defer sfp.Close()

	r := rand.New(rand.NewSource(0))
	var buf [8192]byte
	var buffer bytes.Buffer
	for i := 0; i < 8191; i++ {
		var b [1]byte
		r.Read(b[:])
		_, err := c2p.Write(b[:])
		require.Nil(t, err)

		n, _ := sfp.Read(buf[:])
		buffer.Write(buf[:n])

		_, _, err = transport.WrapConnection(&buffer, sfp, reg.DarkDecoy, manager)
		if !errors.Is(err, transports.ErrTryAgain) {
			t.Fatalf("expected ErrTryAgain, got %v", err)
		}
	}

	_, err = c2p.Write([]byte{0})
	require.Nil(t, err)

	n, _ := sfp.Read(buf[:])
	buffer.Write(buf[:n])
	_, _, err = transport.WrapConnection(&buffer, sfp, reg.DarkDecoy, manager)
	if !errors.Is(err, transports.ErrNotTransport) {
		t.Fatalf("expected ErrNotTransport, got %v", err)
	}
}
