package regprocessor

import (
	"fmt"
	"log"
	"net"
	"testing"
	"time"

	zmq "github.com/pebbe/zmq4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/refraction-networking/conjure/application/transports/wrapping/min"
	pb "github.com/refraction-networking/gotapdance/protobuf"
)

// TODO: Add monitor to RegProcessor and metrics / logging for connections
// that get past the firewall but fail to connect for any reason.

// Mock Socket Configuration of stations connecting to the central ZMQ pubsub
type socketConfig struct {
	address            string
	authenticationType string
	centralPublicKey   string
	stationPrivkeyZ85  string
}

// NOTE: DO NOT DISABLE THIS TEST
//
// If this test is failing, go back and check the changes that you made. Proper authentication for
// the ZMQ sockets is crucial - ensure that this test is passing. If the zmq library updates or the
// RegProcessor interface changes update the test accordingly. In this test the client is the
// stations and the server is the central registration API.
func TestZMQAuth(t *testing.T) {
	nMessages := 10
	zmqBindAddr := "127.0.0.1"
	var zmqPort uint16 = 39_000
	serverAddr := "tcp://" + net.JoinHostPort(zmqBindAddr, fmt.Sprint(zmqPort))

	serverPubkeyZ85, serverPrivkeyZ85, err := zmq.NewCurveKeypair()
	require.Nil(t, err)

	clientPubkeyZ85, clientPrivkeyZ85, err := zmq.NewCurveKeypair()
	require.Nil(t, err)
	otherPubkeyZ85, otherPrivkeyZ85, err := zmq.NewCurveKeypair()
	require.Nil(t, err)

	stationPublicKeys := []string{clientPubkeyZ85}

	done := make(chan struct{})
	next := make(chan struct{})
	ready := make(chan struct{})
	exit := make(chan struct{})

	connectSockets := []struct {
		s   socketConfig
		err error
		c   int
	}{
		{ // correct central server pubkey and registered station key pair. Should work.
			s: socketConfig{
				address:            serverAddr,
				authenticationType: "CURVE",
				centralPublicKey:   serverPubkeyZ85,
				stationPrivkeyZ85:  clientPrivkeyZ85,
			},
			err: nil,
			c:   nMessages,
		},
		{ // correct central server pubkey, but non-registered station key pair
			s: socketConfig{
				address:            serverAddr,
				authenticationType: "CURVE",
				centralPublicKey:   serverPubkeyZ85,
				stationPrivkeyZ85:  otherPrivkeyZ85,
			},
			err: nil,
			c:   0,
		},
		{ // missing central server pubkey and properly registered station key pair
			s: socketConfig{
				address:            serverAddr,
				authenticationType: "CURVE",
				centralPublicKey:   "",
				stationPrivkeyZ85:  clientPrivkeyZ85,
			},
			err: ErrZmqFault, //
			c:   0,
		},
		{ // incorrect central server pubkey and properly registered station public key, using CURVE
			s: socketConfig{
				address:            serverAddr,
				authenticationType: "CURVE",
				centralPublicKey:   otherPubkeyZ85,
				stationPrivkeyZ85:  clientPrivkeyZ85,
			},
			err: nil,
			c:   0,
		},
		{ // incorrect central server pubkey and non-registered station public key, using CURVE
			s: socketConfig{
				address:            serverAddr,
				authenticationType: "CURVE",
				centralPublicKey:   otherPubkeyZ85,
				stationPrivkeyZ85:  otherPrivkeyZ85,
			},
			err: nil,
			c:   0,
		},
		{ // missing central server pubkey and properly registered station public key, NULL
			s: socketConfig{
				address:            serverAddr,
				authenticationType: "NULL",
				centralPublicKey:   "",
				stationPrivkeyZ85:  clientPrivkeyZ85,
			},
			err: nil,
			c:   0,
		},
		{ // incorrect central server pubkey and non-registered station public key, using NULL
			s: socketConfig{
				address:            serverAddr,
				authenticationType: "NULL",
				centralPublicKey:   "",
				stationPrivkeyZ85:  otherPrivkeyZ85,
			},
			err: nil,
			c:   0,
		},
	}

	// Run the RegProcessor as a thread listening on localhost. Sleep for one second then send
	// messages that we expect the station to hear. in production this will be new registrations,
	// here we don't care about the message contents.
	go func() {
		regProcessor, err := newRegProcessor(zmqBindAddr, zmqPort, []byte(zmq.Z85decode(serverPrivkeyZ85)), true, stationPublicKeys)
		require.Nil(t, err)
		defer regProcessor.Close()
		errStation := regProcessor.AddTransport(pb.TransportType_Min, min.Transport{})
		if errStation != nil {
			t.Failed()
			done <- struct{}{}
			exit <- struct{}{}
			return
		}
		ready <- struct{}{}
		for j := 0; j < len(connectSockets); j++ {
			time.Sleep(1 * time.Second)

			for i := 0; i < nMessages; i++ {
				message := fmt.Sprintf("encrypted??: %d", i+j*nMessages)
				// fmt.Printf("sending - %s\n", message)
				_, err := regProcessor.sock.SendBytes([]byte(message), zmq.DONTWAIT)
				if err != nil {
					panic(fmt.Errorf("Publish Error: %w", err))
				}
			}
			time.Sleep(1 * time.Second)
			next <- struct{}{}
		}
		time.Sleep(1 * time.Second)
		done <- struct{}{}
		// fmt.Println("server complete")
		exit <- struct{}{}
	}()

	<-ready
	for i, peerCase := range connectSockets {
		// t.Log("STARTING ", i)
		connectSocket := peerCase.s

		sock, err := zmq.NewSocket(zmq.SUB)
		require.Nil(t, err, "case %d: %s", i, err)

		err = sock.SetHeartbeatIvl(30000 * time.Millisecond)
		require.Nil(t, err, "case %d: %s", i, err)

		err = sock.SetHeartbeatTimeout(1000 * time.Millisecond)
		require.Nil(t, err, "case %d: %s", i, err)

		stationPubkeyZ85, err := zmq.AuthCurvePublic(connectSocket.stationPrivkeyZ85)
		require.Nil(t, err, "case %d: %s", i, err)

		if connectSocket.authenticationType == "CURVE" {
			err = sock.ClientAuthCurve(connectSocket.centralPublicKey, stationPubkeyZ85, connectSocket.stationPrivkeyZ85)
			if peerCase.err != nil {
				require.ErrorIs(t, err, peerCase.err, "case %d: %s", i, err)
				<-next
				// t.Log("NEXT eauth", i)
				continue
			}
			require.Nil(t, err, "case %d: %s", i, err)
		}

		err = sock.SetSubscribe("")
		require.Nil(t, err, "case %d: %s", i, err)

		err = sock.Connect(connectSocket.address)
		if peerCase.err == nil {
			require.Nil(t, err, "case %d: %s", i, err)
		} else {
			require.ErrorIs(t, err, peerCase.err, "expected: %s\n got: %s", peerCase.err, err)
			<-next
			// t.Log("NEXT econn", i)
			continue
		}

		c := make(chan []byte)
		go func() {
			// This go-routine will. live to the end of the test, so as more things are pushed into
			// the zmq publish this will still receive it, HOWEVER, the client(station) portion will
			// have moved on.
			defer sock.Close()
			var err error = nil
			var msg []byte
			for err == nil {
				msg, err = sock.RecvBytes(0)
				if err != nil {
					break
				}
				c <- msg
			}
		}()

		var j int
	L:
		for {
			select {
			case <-c:
				j++
				// t.Logf("%s\n", string(msg))
			case <-next:
				// t.Log("NEXT ", i)
				break L
			case <-done:
				t.Fatal("failed to receive messages")
			}
		}
		assert.Equal(t, peerCase.c, j)
	}
	// t.Log("Client complete")
	<-done
	<-exit
}

func repSocketMonitor(addr string) {
	s, err := zmq.NewSocket(zmq.PAIR)
	if err != nil {
		log.Fatalln(err)
	}
	err = s.Connect(addr)
	if err != nil {
		log.Fatalln(err)
	}
	for {
		a, b, c, err := s.RecvEvent(0)
		if err != nil {
			log.Println(err)
			break
		}
		log.Println(a, b, c)
	}
	s.Close()
}

func TestZmqMonitor(t *testing.T) {

	// REP socket
	rep, err := zmq.NewSocket(zmq.REP)
	if err != nil {
		log.Fatalln(err)
	}

	// REP socket monitor, all events
	err = rep.Monitor("inproc://monitor.rep", zmq.EVENT_ALL)
	if err != nil {
		log.Fatalln(err)
	}
	go repSocketMonitor("inproc://monitor.rep")

	// Generate an event
	err = rep.Bind("tcp://*:5555")
	if err != nil {
		log.Fatalln(err)
	}

	// Allow some time for event detection
	time.Sleep(time.Second)

	rep.Close()
}
