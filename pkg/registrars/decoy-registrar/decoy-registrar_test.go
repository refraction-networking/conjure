package decoy

import (
	"context"
	"encoding/hex"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"

	"github.com/refraction-networking/conjure/internal/conjurepath"
	"github.com/refraction-networking/conjure/pkg/client/assets"
	"github.com/refraction-networking/conjure/pkg/core"
	"github.com/refraction-networking/conjure/pkg/transports/wrapping/min"
	pb "github.com/refraction-networking/conjure/proto"
	td "github.com/refraction-networking/gotapdance/tapdance"
	tls "github.com/refraction-networking/utls"
)

func TestSelectDecoys(t *testing.T) {
	// SelectDecoys(sharedSecret []byte, useV6 bool, width uint) []*pb.TLSDecoySpec
	_, err := assets.AssetsSetDir(conjurepath.Root + "/internal/test_assets")
	require.Nil(t, err)

	seed, err := hex.DecodeString("5a87133b68da3468988a21659a12ed2ece07345c8c1a5b08459ffdea4218d12f")
	require.Nil(t, err)

	decoys, err := selectDecoys(seed, v6, 5)
	require.Nil(t, err)
	require.True(t, len(decoys) >= 5, "Not enough decoys returned from selection.")

	decoys, err = selectDecoys(seed, v4, 5)
	require.Nil(t, err)
	require.True(t, len(decoys) >= 5, "Not enough decoys returned from selection.")
}

func copyFile(fromFile string, toFile string) error {
	from, err := os.Open(fromFile)
	if err != nil {
		return err
	}
	defer from.Close()

	to, err := os.OpenFile(toFile, os.O_RDWR|os.O_CREATE, 0666)
	if err != nil {
		return err
	}
	defer to.Close()

	_, err = io.Copy(to, from)
	return err
}

func TestSelectDecoysErrorHandling(t *testing.T) {
	log.SetOutput(io.Discard)
	defer log.SetOutput(os.Stdout)
	dir := t.TempDir()
	err := copyFile(conjurepath.Root+"/internal/test_assets/ClientConf", dir+"/ClientConf")
	require.Nil(t, err)
	_, err = assets.AssetsSetDir(dir)
	require.Nil(t, err)

	// SelectDecoys(sharedSecret []byte, useV6 bool, width uint)[]*pb.TLSDecoySpec
	seed, err := hex.DecodeString("5a87133b68da3468988a21659a12ed2ece07345c8c1a5b08459ffdea4218d12f")
	require.Nil(t, err)

	// ====[ Assets dir doesn't exist ]=====
	_, err = assets.AssetsSetDir("./non-existent-local-dir")
	require.Contains(t, err.Error(), "no such file or directory")

	// create temporary test dir
	dir = t.TempDir()
	defer os.RemoveAll(dir) // clean up
	_, err = assets.AssetsSetDir(dir)
	require.ErrorIs(t, err, syscall.ENOENT)

	// ====[ ClientConf file doesn't exist ]=====

	// => still using default configuration path since there was not file to update
	decoy, err := selectDecoys(seed, both, 1)
	require.Nil(t, err)
	require.NotNil(t, decoy)
	assert.Equal(t, "tapdance1.freeaeskey.xyz", decoy[0].GetHostname())

	// ====[ ClientConf file not formatted as protobuf ]=====

	tmpfn := filepath.Join(dir, "ClientConf")
	content := []byte("temporary file's content")
	if err := os.WriteFile(tmpfn, content, 0666); err != nil {
		log.Fatal(err)
	}

	// => still using default configuration path since there was not file to update
	decoy, err = selectDecoys(seed, both, 1)
	require.Nil(t, err)
	require.NotNil(t, decoy)
	assert.Equal(t, "tapdance1.freeaeskey.xyz", decoy[0].GetHostname())
}

// TestDecoyRegSendRegistration - Test that the decoy registrar sending a registration request to
// a local mock decoy server. This allows capture of the ClientHello message containing the
// stegonographically encoded registration information. We ensure that this information can be
// extracted as expected and contains the correct information.
func TestDecoyRegSendRegistration(t *testing.T) {
	dir := t.TempDir()
	err := copyFile(conjurepath.Root+"/internal/test_assets/ClientConf", dir+"/ClientConf")
	require.Nil(t, err)
	_, err = assets.AssetsSetDir(dir)
	require.Nil(t, err)

	ctx := context.Background()
	client, server := net.Pipe()
	reg := NewDecoyRegistrar()
	reg.Width = 1
	reg.insecureSkipVerify = true
	pubkey := td.Assets().GetConjurePubkey()

	keys, err := core.GenerateClientSharedKeys(*pubkey)
	require.Nil(t, err)

	session := &td.ConjureSession{
		CovertAddress: "1.1.1.1:443",
		V6Support:     &td.V6{},
		Keys:          keys,
		Transport:     &min.ClientTransport{},
		Dialer: func(ctx context.Context, network string, laddr string, raddr string) (net.Conn, error) {
			return client, nil
		},
	}
	err = reg.PrepareRegKeys(*pubkey, session.Keys.SharedSecret)
	require.Nil(t, err)
	decoy := &pb.TLSDecoySpec{
		Ipv4Addr: proto.Uint32(uint32(0x7f000001)),
		Hostname: proto.String("a.example.com"),
	}

	var stationC2S *pb.ClientToStation
	var expectedKeys *oldSharedKeys
	var wg sync.WaitGroup
	var stationErr error
	wg.Add(1)
	go func() {
		defer wg.Done()
		serverConfig := &tls.Config{
			InsecureSkipVerify: true,
		}
		serverConfig.Certificates = make([]tls.Certificate, 1)
		serverConfig.Certificates[0].Certificate = [][]byte{testECDSACertificate}
		serverConfig.Certificates[0].PrivateKey = testECDSAPrivateKey

		clientData := make([]byte, 10240)
		s := &catchReg{Conn: server, buf: clientData, sharedSecret: session.Keys.SharedSecret}

		l := tls.Server(s, serverConfig)
		if l == nil {
			t.Log("failed to create listener")
			t.Fail()
			return
		}
		defer l.Close()

		ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(5*time.Second))
		defer cancel()

		err := l.HandshakeContext(ctx)
		if err != nil {
			t.Log("failed to handshake", err)
			t.Fail()
			return
		}

		b := make([]byte, 10240)
		_, err = l.Read(b)
		if err != nil {
			t.Log("failed to read", err)
			t.Fail()
			return
		}

		expectedKeys = s.keys
		if s.found {
			stationC2S = s.c2s
		} else {
			stationErr = s.err
		}
	}()

	errch := make(chan error, 1)
	reg.Send(ctx, session, decoy, errch)
	err = <-errch
	require.Nil(t, err)
	wg.Wait()

	require.Nil(t, stationErr)
	require.NotNil(t, expectedKeys)
	require.Equal(t, expectedKeys.SharedSecret, session.Keys.SharedSecret)
	require.Equal(t, expectedKeys.FspIv, reg.fspIv)
	require.Equal(t, expectedKeys.FspKey, reg.fspKey)
	require.Equal(t, expectedKeys.VspIv, reg.vspIv)
	require.Equal(t, expectedKeys.VspKey, reg.vspKey)

	require.NotNil(t, stationC2S)
	require.Equal(t, core.CurrentClientLibraryVersion(), stationC2S.GetClientLibVersion())
	require.Equal(t, pb.TransportType_Min, stationC2S.GetTransport())
	require.Equal(t, pb.TransportType_Min, stationC2S.GetTransport())
	require.Equal(t, "1.1.1.1:443", stationC2S.GetCovertAddress())
	require.Equal(t, td.Assets().GetGeneration(), stationC2S.GetDecoyListGeneration())
}

type catchReg struct {
	// functional
	net.Conn
	sharedSecret []byte

	// packet
	buf         []byte
	n           int
	expectedLen int
	found       bool

	// Result
	c2s  *pb.ClientToStation
	keys *oldSharedKeys
	err  error
}

func (c *catchReg) Read(b []byte) (int, error) {
	nn, err := c.Conn.Read(b)
	if err != nil {
		return nn, err
	}

	if c.found && c.n >= c.expectedLen {
		// we already found the packet containing our registration
		return nn, nil
	}

	// did we get a tls data packet?
	if nn > 5 && b[0] == 0x17 && b[1] == 0x03 && b[2] == 0x03 {

		// Did we recieve the entire packet?
		c.expectedLen = int(b[3])<<8 + int(b[4]) + 5 // plus 5 for TLS header
		if nn < c.expectedLen {
			// if we did not receive the entire packet, copy the data and return
			copy(c.buf, b[:nn])
			c.n += nn
			return nn, nil
		}

		copy(c.buf, b[:c.expectedLen])
		c.n = c.expectedLen

	} else if c.expectedLen != 0 && c.expectedLen > c.n {
		// Did we recieve the entire packet this time?
		if c.n+nn < c.expectedLen {
			// if we did not receive the entire packet, copy the data and return
			copy(c.buf[c.n:], b[:nn])
			c.n += nn
			return nn, nil
		}

		copy(c.buf[c.n:], b[:c.expectedLen-c.n])
		c.n = c.expectedLen
	} else {
		return nn, nil
	}

	// try decrypt with shared secret and generated oldClientSharedKeys
	c.c2s, c.keys, err = tryDecrypt(c.buf[:c.n], c.sharedSecret)
	if err != nil || c.c2s == nil {
		// this is not our packet, return an error and reset the counters
		c.err = err
		// c.found = false
		// c.n = 0
		// c.expectedLen = 0
		return nn, nil
	}

	c.found = true
	c.n = nn

	return nn, err
}
