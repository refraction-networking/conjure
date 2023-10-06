package prefix

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/curve25519"

	"github.com/refraction-networking/conjure/internal/conjurepath"
	tests "github.com/refraction-networking/conjure/internal/testutils"
	"github.com/refraction-networking/conjure/pkg/core"
	"github.com/refraction-networking/conjure/pkg/transports"

	pb "github.com/refraction-networking/conjure/proto"
	"github.com/refraction-networking/ed25519"
	"github.com/refraction-networking/ed25519/extra25519"
)

func TestSuccessfulWrap(t *testing.T) {
	testSubnetPath := conjurepath.Root + "/internal/test_assets/phantom_subnets.toml"
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
	message := []byte(`test message!`)

	for idx := range defaultPrefixes {

		func() {
			var p int32 = int32(idx)
			params := &pb.PrefixTransportParams{PrefixId: &p}
			manager := tests.SetupRegistrationManager(tests.Transport{Index: pb.TransportType_Prefix, Transport: transport})
			c2p, sfp, reg := tests.SetupPhantomConnections(manager, pb.TransportType_Prefix, params, randomizeDstPortMinVersion)
			defer c2p.Close()
			defer sfp.Close()
			require.NotNil(t, reg)

			hmacID := core.ConjureHMAC(reg.Keys.SharedSecret, "PrefixTransportHMACString")

			for id, prefix := range defaultPrefixes {
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
				n, _ := sfp.Read(buf[:])
				buffer := bytes.NewBuffer(buf[:n])

				_, wrapped, err := transport.WrapConnection(buffer, sfp, reg.PhantomIp, manager)
				if id != idx {
					require.ErrorIs(t, err, ErrIncorrectPrefix)
					continue
				} else {
					require.Nil(t, err)
				}

				received := make([]byte, len(message))
				_, err = io.ReadFull(wrapped, received)
				require.Nil(t, err, "failed reading from connection")
				require.True(t, bytes.Equal(message, received), "%s\n%s\n%s", string(message), string(received), prefix.StaticMatch)
			}
		}()
	}
}

func TestUnsuccessfulWrap(t *testing.T) {
	var transport = Transport{
		TagObfuscator:     transports.CTRObfuscator{},
		Privkey:           [32]byte{},
		SupportedPrefixes: defaultPrefixes,
	}

	var p int32 = int32(Min)
	params := &pb.PrefixTransportParams{PrefixId: &p}

	manager := tests.SetupRegistrationManager(tests.Transport{Index: pb.TransportType_Prefix, Transport: transport})
	c2p, sfp, reg := tests.SetupPhantomConnections(manager, pb.TransportType_Prefix, params, randomizeDstPortMinVersion)
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

	var p int32 = int32(Min)
	params := &pb.PrefixTransportParams{PrefixId: &p}

	var err error
	manager := tests.SetupRegistrationManager(tests.Transport{Index: pb.TransportType_Prefix, Transport: transport})
	c2p, sfp, reg := tests.SetupPhantomConnections(manager, pb.TransportType_Prefix, params, randomizeDstPortMinVersion)
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

type ptp = pb.PrefixTransportParams

var f = false
var t = true
var i1 int32 = 1
var in1 int32 = int32(Rand)
var i22 int32 = 22

var _cases = []struct {
	d  string // description
	x  Prefix // Prefix interface in ClientTransport.Prefix
	r  *ptp   // randomize
	p  uint16 // client_port (on getDstPort)
	sp uint16 // server_port (on getDstPort)
	e  error  // client_error (on getDstPort)
	se error  // server_error (on getDstPort)
	ge error  // client GetParams error
}{
	// Nil Prefix w/ and w/out randomization
	{"1", nil, nil, 0, 0, ErrBadParams, ErrBadParams, ErrBadParams},
	{"2", nil, &ptp{RandomizeDstPort: &f}, 0, 443, ErrBadParams, nil, ErrBadParams},   // When using the getter for PrefixTransportParams PrefixID defaults to 0
	{"2", nil, &ptp{RandomizeDstPort: &t}, 0, 58047, ErrBadParams, nil, ErrBadParams}, // When using the getter for PrefixTransportParams PrefixID defaults to 0

	// because the Prefix object is defined the client doesn't care that the id isn't in the
	// set of defaults, because the Prefix can give the dst port.
	{"3", &clientPrefix{[]byte{}, 22, 1025, NoAddedFlush}, &ptp{RandomizeDstPort: &f, PrefixId: &i22}, 1025, 0, nil, ErrUnknownPrefix, ErrUnknownPrefix},
	{"4", &clientPrefix{[]byte{}, 22, 1025, NoAddedFlush}, &ptp{RandomizeDstPort: &t, PrefixId: &i22}, 58047, 0, nil, ErrUnknownPrefix, ErrBadParams},

	// Properly working examples
	{"5", &clientPrefix{[]byte{}, 0, 443, NoAddedFlush}, &ptp{RandomizeDstPort: &t}, 58047, 58047, nil, nil, nil},
	{"6", &clientPrefix{[]byte{}, 0, 443, NoAddedFlush}, &ptp{RandomizeDstPort: &f}, 443, 443, nil, nil, nil},

	// // This will result in a broken connection, valid for both client and server. but unable to
	// // connect since they will disagree about the expected port. This is not taking into account
	// // the overrides system which could also cause this, but will be valid and applied properly
	// // so as not to cause something like this from happening.
	{"7", &clientPrefix{[]byte{}, 0, 1025, NoAddedFlush}, &ptp{RandomizeDstPort: &f}, 1025, 443, nil, nil, nil},
	{"8", &clientPrefix{[]byte{}, 1, 1025, NoAddedFlush}, &ptp{RandomizeDstPort: &f, PrefixId: &i1}, 1025, 80, nil, nil, ErrBadParams},

	// Params nil. Prefix not nil
	{"9", &clientPrefix{[]byte{}, -2, 1025, NoAddedFlush}, nil, 1025, 0, nil, ErrBadParams, ErrUnknownPrefix},
	{"10", &clientPrefix{[]byte{}, -2, 443, NoAddedFlush}, nil, 443, 0, nil, ErrBadParams, nil},

	// Random prefix, resolved by client into another prefix _after_ calling GetParams. This means
	// that ClientTransport.GetParams, and ClientTransport.DstPort are aware of a PrefixID of -1
	// (Rand), but the server side functions (e.g Transport.GetDstPort) are not.
	{"11", &clientPrefix{[]byte{}, -1, 1025, NoAddedFlush}, &ptp{RandomizeDstPort: &t, PrefixId: &in1}, 58047, 58047, nil, ErrUnknownPrefix, nil},
}

func TestPrefixGetDstPortServer(t *testing.T) {
	clv := randomizeDstPortMinVersion
	seed, _ := hex.DecodeString("0000000000000000000000000000000000")
	transport, err := Default([32]byte{})
	require.Nil(t, err)

	for _, testCase := range _cases {
		if testCase.x == nil {
			continue
		}

		// Check server Get destination port
		serverPort, err := transport.GetDstPort(clv, seed, testCase.r)
		if err != nil {
			require.ErrorIs(t, err, testCase.se, testCase.d)
			require.Equal(t, uint16(0), serverPort, testCase.d)
		} else {
			require.Nil(t, err, testCase.d)
			require.Equal(t, testCase.sp, serverPort, testCase.d)
		}

	}
}

func TestPrefixGetDstPortClient(t *testing.T) {
	seed, _ := hex.DecodeString("0000000000000000000000000000000000")

	// Check nil ClientParams
	ct := &ClientTransport{Prefix: DefaultPrefixes[0], parameters: nil}
	err := ct.Prepare(context.Background(), nil)
	require.Nil(t, err)
	port, err := ct.GetDstPort(seed, true)
	require.Nil(t, err)
	require.Equal(t, uint16(443), port)

	for _, testCase := range _cases {
		ct := &ClientTransport{Prefix: testCase.x, parameters: testCase.r}
		err := ct.Prepare(context.Background(), nil)
		require.Nil(t, err)

		// check client get destination.
		clientPort, err := ct.GetDstPort(seed, true)
		if testCase.e != nil {
			require.ErrorIs(t, err, testCase.e, testCase.d)
		} else {
			require.Nil(t, err, testCase.d)
		}
		require.Equal(t, testCase.p, clientPort, testCase.d)
	}
}

func TestPrefixGetParamsClient(t *testing.T) {

	// Check nil clientParams
	ct := &ClientTransport{Prefix: DefaultPrefixes[0], parameters: nil}
	pp, err := ct.GetParams()
	require.Nil(t, err)
	require.NotNil(t, pp)
	require.False(t, pp.(*pb.PrefixTransportParams).GetRandomizeDstPort())

	for _, testCase := range _cases {
		ct := &ClientTransport{Prefix: testCase.x, parameters: testCase.r}

		// Check Client Param parsing
		pp, err := ct.GetParams()
		if err != nil {
			require.ErrorIs(t, err, testCase.ge, testCase.d)
			require.Nil(t, pp)
		}
	}
}

func TestPrefixSetParamsClient(t *testing.T) {
	id := int32(-1)
	params := &pb.PrefixTransportParams{PrefixId: &id}

	ct := &ClientTransport{}
	err := ct.SetParams(params)
	require.Nil(t, err)
	err = ct.Prepare(context.Background(), nil)
	require.Nil(t, err)
	require.NotEqual(t, -1, int(ct.Prefix.ID()))
	require.Equal(t, ct.Prefix.ID(), PrefixID(ct.sessionParams.GetPrefixId()))
	require.Equal(t, Rand, PrefixID(ct.parameters.GetPrefixId()))

	id = int32(Min)
	params = &pb.PrefixTransportParams{PrefixId: &id}

	ct = &ClientTransport{}
	err = ct.SetParams(params)
	require.Nil(t, err)
	require.Equal(t, Min, ct.Prefix.ID())
	require.Equal(t, Min, PrefixID(ct.parameters.GetPrefixId()))
	require.False(t, ct.parameters.GetRandomizeDstPort())

	id = int32(-10) // unknown Prefix ID
	params = &pb.PrefixTransportParams{PrefixId: &id}

	ct = &ClientTransport{}
	err = ct.SetParams(params)
	require.ErrorIs(t, err, ErrUnknownPrefix)
}

func TestClientTransportFromID(t *testing.T) {
	// DefaultPrefixes provides the prefixes supported by default for use when by the client.
	DefaultPrefixes = make(map[PrefixID]Prefix)

	_, err := TryFromID(Min)
	require.ErrorIs(t, err, ErrUnknownPrefix)
	_, err = TryFromID(Rand)
	require.ErrorIs(t, err, ErrUnknownPrefix)

	applyDefaultPrefixes()

	_, err = TryFromID(-2)
	require.ErrorIs(t, err, ErrUnknownPrefix)

	_, err = TryFromID(PrefixID((len(defaultPrefixes) + 10)))
	require.ErrorIs(t, err, ErrUnknownPrefix)

	_, err = TryFromID(Rand)
	require.Nil(t, err)

	p, err := TryFromID(Min)
	require.Nil(t, err)
	require.Equal(t, &clientPrefix{defaultPrefixes[0].StaticMatch, 0, 443, NoAddedFlush}, p)

	p, err = TryFromID(OpenSSH2)
	require.Nil(t, err)
	require.Equal(t, &clientPrefix{defaultPrefixes[OpenSSH2].StaticMatch, OpenSSH2, 22, NoAddedFlush}, p)

	b, _ := hex.DecodeString("010000")
	r := bytes.NewReader(b)
	p, err = pickRandomPrefix(r)
	require.Nil(t, err)
	require.Equal(t, &clientPrefix{defaultPrefixes[1].StaticMatch, 1, 80, NoAddedFlush}, p)
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

// Test End to End client WrapConn to Server WrapConnection
func TestPrefixEndToEnd(t *testing.T) {
	testSubnetPath := conjurepath.Root + "/internal/test_assets/phantom_subnets.toml"
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
	message := []byte(`test message!`)

	for _, flushPolicy := range []int32{DefaultFlush, NoAddedFlush, FlushAfterPrefix} {
		for idx := range defaultPrefixes {

			t.Logf("testing prefix %d, %s", idx, idx.Name())

			var p int32 = int32(idx)
			params := &pb.PrefixTransportParams{PrefixId: &p, CustomFlushPolicy: &flushPolicy}
			manager := tests.SetupRegistrationManager(tests.Transport{Index: pb.TransportType_Prefix, Transport: transport})
			c2p, sfp, reg := tests.SetupPhantomConnections(manager, pb.TransportType_Prefix, params, uint(core.CurrentClientLibraryVersion()))
			defer c2p.Close()
			defer sfp.Close()
			require.NotNil(t, reg)
			sch := make(chan struct{}, 1)

			go func() {
				var c net.Conn
				var err error
				var buf [4096]byte
				received := bytes.Buffer{}

				sch <- struct{}{}
				for {
					n, err := sfp.Read(buf[:])
					if err != nil {
						t.Errorf("error reading from server connection after %d bytes %s", n, err)
						t.Fail()
						return
					}

					received.Write(buf[:n])
					_, c, err = transport.WrapConnection(&received, sfp, reg.PhantomIp, manager)
					if err == nil {
						break
					} else if !errors.Is(err, transports.ErrTryAgain) {
						t.Errorf("error getting wrapped connection %s - expected %s, %d", err, idx.Name(), flushPolicy)
						t.Fail()
						return
					}
				}

				recvBuf := make([]byte, len(message))
				_, err = io.ReadFull(c, recvBuf)
				require.Nil(t, err, "failed reading from server connection")
				_, err = c.Write(recvBuf)
				require.Nil(t, err, "failed writing to server connection")
			}()

			<-sch
			clientPrefix, err := TryFromID(PrefixID(p))
			require.Nil(t, err)
			ClientTransport := &ClientTransport{Prefix: clientPrefix, parameters: params}
			err = ClientTransport.PrepareKeys(curve25519Public, reg.Keys.SharedSecret, reg.Keys.TransportReader)
			require.Nil(t, err)
			clientConn, err := ClientTransport.WrapConn(c2p)
			require.Nil(t, err, "error getting wrapped connection")

			err = clientConn.SetDeadline(time.Now().Add(3 * time.Second))
			require.Nil(t, err, "error setting deadline")

			_, err = clientConn.Write(message)
			require.Nil(t, err, "failed writing to client connection")
			cbuf := make([]byte, len(message))
			_, err = io.ReadFull(clientConn, cbuf)
			require.Nil(t, err, "failed reading from client connection")
			require.True(t, bytes.Equal(message, cbuf), "%s\n%s", string(message), string(cbuf))
		}
	}
}
