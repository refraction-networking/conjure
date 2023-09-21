package integration_test

import (
	"bytes"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/refraction-networking/conjure/internal/conjurepath"
	"github.com/refraction-networking/conjure/internal/testutils"
	"github.com/refraction-networking/conjure/pkg/core"
	"github.com/refraction-networking/conjure/pkg/core/interfaces"
	"github.com/refraction-networking/conjure/pkg/log"
	"github.com/refraction-networking/conjure/pkg/station/lib"
	"github.com/refraction-networking/conjure/pkg/transports"
	"github.com/refraction-networking/conjure/pkg/transports/wrapping/min"
	"github.com/refraction-networking/conjure/pkg/transports/wrapping/obfs4"
	"github.com/refraction-networking/conjure/pkg/transports/wrapping/prefix"
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

type TestParams interface {
	// GetParams returns the protobuf representation of the parameters
	GetParams() any
	String() string
}

type stationBuilder = func([32]byte) lib.WrappingTransport

func TestTransportsEndToEnd(t *testing.T) {
	if *debug {
		log.SetLevel(log.DebugLevel)
	}
	testCases := []struct {
		stationTransportBuilder     stationBuilder
		clientTransport             interfaces.WrappingTransport
		clientParamPermuteGenerator func() []TestParams
	}{
		{
			func(privKey [32]byte) lib.WrappingTransport {
				tr, err := prefix.Default(privKey)
				require.Nil(t, err)
				return tr
			},
			&prefix.ClientTransport{},
			prefixClientParamPermutations,
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
func testTransportsEndToEnd(t *testing.T, builder stationBuilder, clientTransport interfaces.WrappingTransport, clientParamPermuteGenerator func() []TestParams) {
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
	paramSet := append([]TestParams{nil}, clientParamPermuteGenerator()...)

	// for _, flushPolicy := range []int32{DefaultFlush, NoAddedFlush, FlushAfterPrefix} {
	// 	for idx := range defaultPrefixes {
	for _, testParams := range paramSet {

		if testParams == nil {
			testParams = &nilParams{}
		}
		params := testParams.GetParams()
		clientKeys, err := core.GenerateClientSharedKeys(curve25519Public)
		require.Nil(t, err)

		err = clientTransport.SetParams(params)
		require.Nil(t, err)
		protoParams, err := clientTransport.GetParams()
		require.Nil(t, err)
		t.Logf("running %s w/ %s", clientTransport.Name(), testParams.String())

		manager := testutils.SetupRegistrationManager(testutils.Transport{Index: pb.TransportType_Prefix, Transport: transport})
		require.NotNil(t, manager)
		c2p, sfp, serverReg := testutils.SetupPhantomConnectionsSecret(manager, pb.TransportType_Prefix, protoParams, clientKeys.SharedSecret, uint(core.CurrentClientLibraryVersion()), testutils.TestSubnetPath)
		defer c2p.Close()
		defer sfp.Close()
		require.NotNil(t, serverReg)
		sch := make(chan struct{}, 1)
		go func() {

			var c net.Conn
			var err error
			var buf [10240]byte
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
				_, c, err = transport.WrapConnection(&received, sfp, serverReg.PhantomIp, manager)
				if err == nil {
					break
				} else if !errors.Is(err, transports.ErrTryAgain) {
					if prm, ok := params.(*prefix.ClientParams); ok {
						t.Errorf("error getting wrapped connection %s - expected %s, %d", err, prefix.PrefixID(prm.PrefixID).Name(), prm.FlushPolicy)
					} else if prm, ok := params.(*pb.PrefixTransportParams); ok {
						t.Errorf("error getting wrapped connection %s - expected %s, %d", err, prefix.PrefixID(prm.GetPrefixId()).Name(), prm.GetCustomFlushPolicy())
					} else {
						t.Errorf("error getting wrapped connection %s", err)
					}
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
		clientErr := clientTransport.PrepareKeys(curve25519Public, serverReg.Keys.SharedSecret, clientKeys.Reader)
		require.Nil(t, clientErr)

		clientErr = c2p.SetDeadline(time.Now().Add(15 * time.Second))
		require.Nil(t, clientErr)

		clientConn, clientErr := clientTransport.WrapConn(c2p)
		require.Nil(t, clientErr, "error getting wrapped connection")
		require.NotNil(t, clientConn, "returned client wrapped connection nil")

		_, clientErr = clientConn.Write(message)
		require.Nil(t, clientErr, "failed writing to client connection")

		cbuf := make([]byte, len(message))
		_, clientErr = io.ReadFull(clientConn, cbuf)
		require.Nil(t, clientErr, "failed reading from client connection")
		require.True(t, bytes.Equal(message, cbuf), "%s\n%s", string(message), string(cbuf))
	}
}

func genericParamPermutations() []TestParams {
	return []TestParams{
		&genericParams{
			&pb.GenericTransportParams{
				RandomizeDstPort: &_true,
			}},
		&genericParams{
			&pb.GenericTransportParams{
				RandomizeDstPort: &_false,
			}},
	}
}

type nilParams struct{}

func (p *nilParams) GetParams() any {
	return nil
}

func (p *nilParams) String() string {
	return "nil"
}

type genericParams struct {
	*pb.GenericTransportParams
}

func (p *genericParams) GetParams() any {
	return p.GenericTransportParams
}

func (p *genericParams) String() string {
	return fmt.Sprintf("randDstPort: %t", p.GetRandomizeDstPort())
}

// ClientParamPermutations returns a list of client parameters for inclusions in tests that require
// variance.
func prefixClientParamPermutations() []TestParams {
	paramSet := []TestParams{}
	for _, flushPolicy := range []int32{prefix.DefaultFlush, prefix.NoAddedFlush, prefix.FlushAfterPrefix} {
		for idx := prefix.Rand; idx <= prefix.OpenSSH2; idx++ {
			for _, rand := range []bool{true, false} {
				var p int32 = int32(idx)
				params := &prefix.ClientParams{
					PrefixID:         p,
					RandomizeDstPort: rand,
					FlushPolicy:      flushPolicy,
				}
				paramSet = append(paramSet, params)
			}
		}
	}
	return paramSet
}
