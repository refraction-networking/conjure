package decoy

import (
	"context"
	"crypto/x509"
	"encoding/hex"
	"fmt"
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
		V6Support: &td.V6{},
		Keys:      keys,
		Transport: &min.ClientTransport{},
		Dialer: func(ctx context.Context, network string, laddr string, raddr string) (net.Conn, error) {
			return client, nil
		},
	}
	reg.PrepareRegKeys(*pubkey, session.Keys.SharedSecret)
	decoy := &pb.TLSDecoySpec{
		Ipv4Addr: proto.Uint32(uint32(0x7f000001)),
		Hostname: proto.String("a.example.com"),
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		serverConfig := &tls.Config{
			InsecureSkipVerify: true,
		}
		serverConfig.Certificates = make([]tls.Certificate, 1)
		serverConfig.Certificates[0].Certificate = [][]byte{testECDSACertificate}
		serverConfig.Certificates[0].PrivateKey = testECDSAPrivateKey

		clientHello := make([]byte, 10240)
		s := &wrapFirst{Conn: server, buf: clientHello}

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
		t.Logf("bytes: %s", string(hex.EncodeToString(clientHello[:s.n])))

		b := make([]byte, 1024)
		_, err = l.Read(b)
		if err != nil {
			t.Log("failed to read", err)
			t.Fail()
			return
		}
	}()

	errch := make(chan error, 1)
	reg.Send(ctx, session, decoy, errch)
	err = <-errch
	require.Nil(t, err)
	wg.Wait()
}

var testECDSAPrivateKey, _ = x509.ParseECPrivateKey(fromHex("3081dc0201010442019883e909ad0ac9ea3d33f9eae661f1785206970f8ca9a91672f1eedca7a8ef12bd6561bb246dda5df4b4d5e7e3a92649bc5d83a0bf92972e00e62067d0c7bd99d7a00706052b81040023a18189038186000400c4a1edbe98f90b4873367ec316561122f23d53c33b4d213dcd6b75e6f6b0dc9adf26c1bcb287f072327cb3642f1c90bcea6823107efee325c0483a69e0286dd33700ef0462dd0da09c706283d881d36431aa9e9731bd96b068c09b23de76643f1a5c7fe9120e5858b65f70dd9bd8ead5d7f5d5ccb9b69f30665b669a20e227e5bffe3b"))
var testECDSACertificate = fromHex("3082020030820162020900b8bf2d47a0d2ebf4300906072a8648ce3d04013045310b3009060355040613024155311330110603550408130a536f6d652d53746174653121301f060355040a1318496e7465726e6574205769646769747320507479204c7464301e170d3132313132323135303633325a170d3232313132303135303633325a3045310b3009060355040613024155311330110603550408130a536f6d652d53746174653121301f060355040a1318496e7465726e6574205769646769747320507479204c746430819b301006072a8648ce3d020106052b81040023038186000400c4a1edbe98f90b4873367ec316561122f23d53c33b4d213dcd6b75e6f6b0dc9adf26c1bcb287f072327cb3642f1c90bcea6823107efee325c0483a69e0286dd33700ef0462dd0da09c706283d881d36431aa9e9731bd96b068c09b23de76643f1a5c7fe9120e5858b65f70dd9bd8ead5d7f5d5ccb9b69f30665b669a20e227e5bffe3b300906072a8648ce3d040103818c0030818802420188a24febe245c5487d1bacf5ed989dae4770c05e1bb62fbdf1b64db76140d311a2ceee0b7e927eff769dc33b7ea53fcefa10e259ec472d7cacda4e970e15a06fd00242014dfcbe67139c2d050ebd3fa38c25c13313830d9406bbd4377af6ec7ac9862eddd711697f857c56defb31782be4c7780daecbbe9e4e3624317b6a0f399512078f2a")

func fromHex(s string) []byte {
	b, _ := hex.DecodeString(s)
	return b
}

type wrapFirst struct {
	net.Conn
	buf []byte
	n   int
}

func (c *wrapFirst) Read(b []byte) (int, error) {
	nn, err := c.Conn.Read(b)
	if err != nil {
		return nn, err
	}

	if nn > len(c.buf) {
		return nn, fmt.Errorf("incoming bytes do not fit in buffer %d > %d", nn, len(c.buf))
	}

	// copy the bytes read to the buffer
	n := copy(c.buf, b[:nn])
	if n != nn {
		return nn, fmt.Errorf("failed to copy bytes to buf %d != %d", n, nn)
	}
	c.n = nn
	return nn, nil
}
