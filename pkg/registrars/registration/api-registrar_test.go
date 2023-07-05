package registration

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	transports "github.com/refraction-networking/conjure/pkg/transports/client"
	pb "github.com/refraction-networking/conjure/proto"
	"github.com/refraction-networking/gotapdance/tapdance"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestAPIRegistrar(t *testing.T) {
	_ = transports.EnableDefaultTransports()

	transport, err := transports.New("min")
	require.Nil(t, err)

	session := tapdance.MakeConjureSession("1.2.3.4:1234", transport)

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Fatalf("incorrect request method: expected POST, got %v", r.Method)
		}

		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("failed to read request body: %v", err)
		}

		payload := pb.C2SWrapper{}
		err = proto.Unmarshal(body, &payload)
		if err != nil {
			t.Fatalf("failed to decode request body: %v", err)
		}

		if payload.RegistrationPayload.GetCovertAddress() != "1.2.3.4:1234" {
			t.Fatalf("incorrect covert address: expected 1.2.3.4:1234, got %s", payload.RegistrationPayload.GetCovertAddress())
		}

		if !bytes.Equal(payload.GetSharedSecret(), session.Keys.SharedSecret) {
			t.Fatalf("incorrect shared secret: expected %v, got %v", session.Keys.SharedSecret, payload.GetSharedSecret())
		}
	}))

	registrar := APIRegistrar{
		endpoint:      server.URL,
		client:        server.Client(),
		bidirectional: false,
		logger:        logrus.New(),
	}

	_, err = registrar.Register(session, context.TODO())
	require.Nil(t, err)

	server.Close()
}

func TestAPIRegistrarBidirectional(t *testing.T) {
	_ = transports.EnableDefaultTransports()

	transport, err := transports.New("min")
	require.Nil(t, err)
	// Make Conjure session with covert address
	session := tapdance.MakeConjureSession("1.2.3.4:1234", transport)
	addr4 := binary.BigEndian.Uint32(net.ParseIP("127.0.0.1").To4())
	addr6 := net.ParseIP("2001:48a8:687f:1:41d3:ff12:45b:73c8")
	var port uint32 = 80

	// Create mock server
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check that method is what we expect
		if r.Method != "POST" {
			t.Fatalf("incorrect request method: expected POST, got %v", r.Method)
		}

		// Read in request as server
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("failed to read request body: %v", err)
		}

		// Make payload for registration
		payload := pb.C2SWrapper{}
		err = proto.Unmarshal(body, &payload)
		if err != nil {
			t.Fatalf("failed to decode request body: %v", err)
		}

		if payload.RegistrationPayload.GetCovertAddress() != "1.2.3.4:1234" {
			t.Fatalf("incorrect covert address: expected 1.2.3.4:1234, got %s", payload.RegistrationPayload.GetCovertAddress())
		}

		if !bytes.Equal(payload.GetSharedSecret(), session.Keys.SharedSecret) {
			t.Fatalf("incorrect shared secret: expected %v, got %v", session.Keys.SharedSecret, payload.GetSharedSecret())
		}

		regResp := &pb.RegistrationResponse{
			DstPort:  &port,
			Ipv4Addr: &addr4,
			Ipv6Addr: []byte(addr6.To16()),
		}

		t.Logf("IPv6 address %v -----> %v", addr6, regResp.Ipv6Addr)

		body, _ = proto.Marshal(regResp)
		_, err = w.Write(body)
		require.Nil(t, err)
	}))

	registrar := APIRegistrar{
		endpoint:      server.URL,
		client:        server.Client(),
		bidirectional: true,
		logger:        logrus.New(),
	}

	// register.Register() connects to server set up above and sends registration info
	// "response" will store the RegistrationResponse protobuf that the server replies with
	response, err := registrar.Register(session, context.TODO())
	if err != nil {
		t.Fatalf("bidirectional registrar failed with error: %v", err)
	}

	if response.Phantom4() == nil {
		t.Fatal("phantom4 is nil")
	} else if response.Phantom4().String() != "127.0.0.1" {
		t.Fatalf("phantom4 is wrong %v", response.Phantom4().String())
	}
	if response.Phantom6() == nil {
		t.Fatal("phantom6 is nil")
	} else if response.Phantom6().String() != "2001:48a8:687f:1:41d3:ff12:45b:73c8" {
		t.Fatalf("%v phantom6 is wrong\n expected: %v", response.Phantom6().String(), "2001:48a8:687f:1:41d3:ff12:45b:73c8")

	}

	server.Close()
}
