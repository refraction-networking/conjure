package decoy

import (
	"encoding/hex"
	"io"
	"log"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/refraction-networking/conjure/internal/conjurepath"
	"github.com/refraction-networking/conjure/pkg/client/assets"
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
