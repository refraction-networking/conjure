package obfs4

import (
	"bytes"
	"errors"
	"io"
	"log"
	"math/rand"
	"net"
	"testing"
	"time"

	"github.com/refraction-networking/conjure/application/transports"
	"github.com/refraction-networking/conjure/application/transports/wrapping/internal/tests"
	pb "github.com/refraction-networking/gotapdance/protobuf"

	pt "git.torproject.org/pluggable-transports/goptlib.git"
	"gitlab.com/yawning/obfs4.git/transports/obfs4"
)

func wrapConnection(conn net.Conn, nodeID, publicKey string, wrapped chan (net.Conn)) {
	args := pt.Args{}
	args.Add("node-id", nodeID)
	args.Add("public-key", publicKey)
	args.Add("iat-mode", "1")

	t := obfs4.Transport{}
	c, err := t.ClientFactory("")
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
	var transport Transport
	manager := tests.SetupRegistrationManager(tests.Transport{Index: pb.TransportType_Obfs4, Transport: transport})
	c2p, sfp, reg := tests.SetupPhantomConnections(manager, pb.TransportType_Obfs4)
	defer c2p.Close()
	defer sfp.Close()

	wrappedc2p := make(chan net.Conn)
	go wrapConnection(c2p, reg.Keys.Obfs4Keys.NodeID.Hex(), reg.Keys.Obfs4Keys.PublicKey.Hex(), wrappedc2p)

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
	c2p.Write(message)

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
	manager := tests.SetupRegistrationManager(tests.Transport{Index: pb.TransportType_Obfs4, Transport: transport})
	c2p, sfp, reg := tests.SetupPhantomConnections(manager, pb.TransportType_Obfs4)
	defer c2p.Close()
	defer sfp.Close()

	io.Copy(c2p, io.LimitReader(rand.New(rand.NewSource(0)), 8192))

	var buf [8192]byte
	var buffer bytes.Buffer
	n, _ := io.ReadFull(sfp, buf[:])
	buffer.Write(buf[:n])

	_, _, err := transport.WrapConnection(&buffer, sfp, reg.DarkDecoy, manager)
	if !errors.Is(err, transports.ErrNotTransport) {
		t.Fatalf("expected ErrNotTransport, got %v", err)
	}
}

func TestTryAgain(t *testing.T) {
	var transport Transport
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
		c2p.Write(b[:])

		n, _ := sfp.Read(buf[:])
		buffer.Write(buf[:n])

		_, _, err := transport.WrapConnection(&buffer, sfp, reg.DarkDecoy, manager)
		if !errors.Is(err, transports.ErrTryAgain) {
			t.Fatalf("expected ErrTryAgain, got %v", err)
		}
	}

	c2p.Write([]byte{0})

	n, _ := sfp.Read(buf[:])
	buffer.Write(buf[:n])
	_, _, err := transport.WrapConnection(&buffer, sfp, reg.DarkDecoy, manager)
	if !errors.Is(err, transports.ErrNotTransport) {
		t.Fatalf("expected ErrNotTransport, got %v", err)
	}
}
