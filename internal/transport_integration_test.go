package integration_test

import (
	"bytes"
	"crypto/rand"
	"errors"
	"flag"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/refraction-networking/conjure/internal/conjurepath"
	"github.com/refraction-networking/conjure/internal/testutils"
	"github.com/refraction-networking/conjure/pkg/core"
	"github.com/refraction-networking/conjure/pkg/core/interfaces"
	"github.com/refraction-networking/conjure/pkg/station/lib"
	"github.com/refraction-networking/conjure/pkg/station/log"
	"github.com/refraction-networking/conjure/pkg/transports"
	"github.com/refraction-networking/conjure/pkg/transports/wrapping/min"
	"github.com/refraction-networking/conjure/pkg/transports/wrapping/obfs4"
	"github.com/refraction-networking/conjure/pkg/transports/wrapping/prefix"
	prefixTest "github.com/refraction-networking/conjure/pkg/transports/wrapping/prefix/test"
	pb "github.com/refraction-networking/conjure/proto"
	"github.com/refraction-networking/ed25519"
	"github.com/refraction-networking/ed25519/extra25519"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/curve25519"
)

var (
	debug       = flag.Bool("debug", false, "enable debug logging")
	_true  bool = true
	_false bool = false
)

type stationBuilder = func([32]byte) lib.WrappingTransport

func TestTransportsEndToEnd(t *testing.T) {
	if *debug {
		log.SetLevel(log.DebugLevel)
	}
	testCases := []struct {
		stationTransportBuilder     stationBuilder
		clientTransport             interfaces.WrappingTransport
		clientParamPermuteGenerator func() []any
	}{
		{
			func(privKey [32]byte) lib.WrappingTransport {
				tr, err := prefix.Default(privKey)
				require.Nil(t, err)
				return tr
			},
			&prefix.ClientTransport{},
			prefixTest.ClientParamPermutations,
		},
		{
			func(privKey [32]byte) lib.WrappingTransport {
				return &obfs4.Transport{}
			},
			&obfs4.ClientTransport{},
			genericParamPermutations,
		},
		{
			func(privKey [32]byte) lib.WrappingTransport {
				return &min.Transport{}
			},
			&min.ClientTransport{},
			genericParamPermutations,
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.clientTransport.Name(), func(t *testing.T) {
			testTransportsEndToEnd(t, testCase.stationTransportBuilder, testCase.clientTransport, testCase.clientParamPermuteGenerator)
		})
	}
}

// Test End to End client WrapConn to Server WrapConnection
func testTransportsEndToEnd(t *testing.T, builder stationBuilder, clientTransport interfaces.WrappingTransport, clientParamPermuteGenerator func() []any) {
	testSubnetPath := conjurepath.Root + "/pkg/station/lib/test/phantom_subnets.toml"
	os.Setenv("PHANTOM_SUBNET_LOCATION", testSubnetPath)

	_, private, _ := ed25519.GenerateKey(rand.Reader)

	var curve25519Public, curve25519Private [32]byte
	extra25519.PrivateKeyToCurve25519(&curve25519Private, private)
	curve25519.ScalarBaseMult(&curve25519Public, &curve25519Private)

	message := []byte(`test message!`)

	transport := builder(curve25519Private)

	// Ensure that we test all given parameter permutations as well as nil params
	// paramSet := append([]any{nil}, clientParamPermuteGenerator())
	paramSet := append([]any{nil}, clientParamPermuteGenerator()...)

	// for _, flushPolicy := range []int32{DefaultFlush, NoAddedFlush, FlushAfterPrefix} {
	// 	for idx := range defaultPrefixes {
	for _, params := range paramSet {

		err := clientTransport.SetParams(params)
		require.Nil(t, err)
		protoParams, err := clientTransport.GetParams()
		require.Nil(t, err)

		manager := testutils.SetupRegistrationManager(testutils.Transport{Index: pb.TransportType_Prefix, Transport: transport})
		require.NotNil(t, manager)
		c2p, sfp, reg := testutils.SetupPhantomConnections(manager, pb.TransportType_Prefix, protoParams, uint(core.CurrentClientLibraryVersion()))
		defer c2p.Close()
		defer sfp.Close()
		require.NotNil(t, reg)

		go func() {

			var c net.Conn
			var err error
			var buf [10240]byte
			var nRead = 0
			for {
				n, _ := sfp.Read(buf[:])
				// t.Logf("%d %s\t %s", n, hex.EncodeToString(buf[:n]), string(buf[:n]))
				buffer := bytes.NewBuffer(buf[nRead : nRead+n])
				nRead += n

				_, c, err = transport.WrapConnection(buffer, sfp, reg.PhantomIp, manager)
				if err == nil {
					break
				} else if !errors.Is(err, transports.ErrTryAgain) {
					t.Errorf("error getting wrapped connection %s", err)
					t.Fail()
					return
				}
			}

			received := make([]byte, len(message))
			_, err = io.ReadFull(c, received)
			require.Nil(t, err, "failed reading from server connection")
			_, err = c.Write(received)
			require.Nil(t, err, "failed writing to server connection")
		}()

		err = clientTransport.PrepareKeys(curve25519Public, reg.Keys.SharedSecret, reg.Keys.TransportReader)
		require.Nil(t, err)

		err = c2p.SetDeadline(time.Now().Add(15 * time.Second))
		require.Nil(t, err)

		clientConn, err := clientTransport.WrapConn(c2p)
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

func genericParamPermutations() []any {
	return []any{
		&pb.GenericTransportParams{
			RandomizeDstPort: &_true,
		},
		&pb.GenericTransportParams{
			RandomizeDstPort: &_false,
		},
	}
}
