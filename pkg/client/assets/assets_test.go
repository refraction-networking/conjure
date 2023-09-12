package assets

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path"
	"syscall"
	"testing"

	"github.com/refraction-networking/conjure/internal/conjurepath"
	"github.com/refraction-networking/conjure/pkg/log"
	pb "github.com/refraction-networking/conjure/proto"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

func TestAssets_Decoys(t *testing.T) {
	var b bytes.Buffer
	var err error
	logHolder := bufio.NewWriter(&b)
	log.SetOutput(logHolder)
	defer log.SetOutput(os.Stdout)

	dir1 := t.TempDir()
	dir2 := t.TempDir()

	var testDecoys1 = []*pb.TLSDecoySpec{
		pb.InitTLSDecoySpec("4.8.15.16", "ericw.us"),
		pb.InitTLSDecoySpec("19.21.23.42", "blahblahbl.ah"),
	}

	var testDecoys2 = []*pb.TLSDecoySpec{
		pb.InitTLSDecoySpec("0.1.2.3", "whatever.cn"),
		pb.InitTLSDecoySpec("255.254.253.252", "particular.ir"),
		pb.InitTLSDecoySpec("11.22.33.44", "what.is.up"),
		pb.InitTLSDecoySpec("8.255.255.8", "heh.meh"),
	}

	_, err = AssetsSetDir(dir1)
	if err != nil && !errors.Is(err, syscall.ENOENT) {
		// No ClientConf exists in dir1 yet so ENOENT is expected
		t.Log("unexpected error occurred:", err)
		t.Fail()
	}

	err = Assets().SetDecoys(testDecoys1)
	require.Nil(t, err)

	if !Assets().IsDecoyInList(pb.InitTLSDecoySpec("19.21.23.42", "blahblahbl.ah")) {
		t.Fatal("Decoy 19.21.23.42(blahblahbl.ah) is NOT in Decoy List!")
	}
	_, err = AssetsSetDir(dir2)
	if err != nil && !errors.Is(err, syscall.ENOENT) {
		// No ClientConf exists in dir2 yet so ENOENT is expected
		t.Log("unexpected error occurred:", err)
		t.Fail()
	}

	err = Assets().SetDecoys(testDecoys2)
	require.Nil(t, err)

	if Assets().IsDecoyInList(pb.InitTLSDecoySpec("19.21.23.42", "blahblahbl.ah")) {
		t.Fatal("Decoy 19.21.23.42(blahblahbl.ah) is in Decoy List!")
	}
	if !Assets().IsDecoyInList(pb.InitTLSDecoySpec("11.22.33.44", "what.is.up")) {
		t.Fatal("Decoy 11.22.33.44(what.is.up) is NOT in Decoy List!")
	}

	decoyInList := func(d *pb.TLSDecoySpec, decoyList []*pb.TLSDecoySpec) bool {
		for _, elem := range decoyList {
			if proto.Equal(elem, d) {
				return true
			}
		}
		return false
	}

	for i := 0; i < 10; i++ {
		_sni, addr := Assets().GetDecoyAddress()
		hostAddr, _, err := net.SplitHostPort(addr)
		if err != nil {
			t.Fatal("Corrupted addr:", addr, ". Error:", err.Error())
		}
		decoyServ := pb.InitTLSDecoySpec(hostAddr, _sni)
		if !decoyInList(decoyServ, Assets().config.DecoyList.TlsDecoys) {
			fmt.Println("decoyServ not in List!")
			fmt.Println("decoyServ:", decoyServ)
			fmt.Println("Assets().decoys:", Assets().config.DecoyList.TlsDecoys)
			t.Fail()
		}
	}
	_, err = AssetsSetDir(dir1)
	require.Nil(t, err)

	if !Assets().IsDecoyInList(pb.InitTLSDecoySpec("19.21.23.42", "blahblahbl.ah")) {
		t.Fatal("Decoy 19.21.23.42(blahblahbl.ah) is NOT in Decoy List!")
	}
	if Assets().IsDecoyInList(pb.InitTLSDecoySpec("11.22.33.44", "what.is.up")) {
		t.Fatal("Decoy 11.22.33.44(what.is.up) is in Decoy List!")
	}
	for i := 0; i < 10; i++ {
		_sni, addr := Assets().GetDecoyAddress()
		hostAddr, _, err := net.SplitHostPort(addr)
		if err != nil {
			t.Fatal("Corrupted addr:", addr, ". Error:", err.Error())
		}
		decoyServ := pb.InitTLSDecoySpec(hostAddr, _sni)
		if !decoyInList(decoyServ, Assets().config.DecoyList.TlsDecoys) {
			fmt.Println("decoyServ not in List!")
			fmt.Println("decoyServ:", decoyServ)
			fmt.Println("Assets().decoys:", Assets().config.DecoyList.TlsDecoys)
			t.Fail()
		}
	}
	os.Remove(path.Join(dir1, Assets().filenameClientConf))
	os.Remove(path.Join(dir2, Assets().filenameClientConf))
	os.Remove(dir1)
	os.Remove(dir2)
}

func TestAssets_Pubkey(t *testing.T) {
	var err error
	var b bytes.Buffer
	logHolder := bufio.NewWriter(&b)
	log.SetOutput(logHolder)
	defer log.SetOutput(os.Stdout)

	initPubKey := func(defaultKey []byte) *pb.PubKey {
		defualtKeyType := pb.KeyType_AES_GCM_128
		return &pb.PubKey{Key: defaultKey, Type: &defualtKeyType}
	}
	_ = Assets()
	dir1 := t.TempDir()
	dir2 := t.TempDir()

	var pubkey1 = initPubKey([]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11,
		12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26,
		27, 28, 29, 30, 31})
	var pubkey2 = initPubKey([]byte{200, 201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211,
		212, 213, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223, 224, 225, 226,
		227, 228, 229, 230, 231})

	_, err = AssetsSetDir(dir1)
	if err != nil && !errors.Is(err, syscall.ENOENT) {
		// No ClientConf exists in dir1 yet so ENOENT is expected
		t.Log("unexpected error occurred:", err)
		t.Fail()
	}

	err = Assets().SetPubkey(pubkey1)
	require.Nil(t, err)

	_, err = AssetsSetDir(dir2)
	if err != nil && !errors.Is(err, syscall.ENOENT) {
		// No ClientConf exists in dir2 yet so ENOENT is expected
		t.Log("unexpected error occurred:", err)
		t.Fail()
	}

	err = Assets().SetPubkey(pubkey2)
	require.Nil(t, err)

	if !bytes.Equal(Assets().config.DefaultPubkey.Key[:], pubkey2.Key[:]) {
		t.Log("Pubkeys are not equal!")
		t.Log("Assets().stationPubkey:", Assets().config.DefaultPubkey.Key[:])
		t.Log("pubkey2:", pubkey2)
		t.Fail()
	}

	_, err = AssetsSetDir(dir1)
	require.Nil(t, err)

	if !bytes.Equal(Assets().config.DefaultPubkey.Key[:], pubkey1.Key[:]) {
		t.Log("Pubkeys are not equal!")
		t.Log("Assets().stationPubkey:", Assets().config.DefaultPubkey.Key[:])
		t.Log("pubkey1:", pubkey1)
		t.Fail()
	}
	// os.Remove(path.Join(dir1, Assets().filenameStationPubkey))
	// os.Remove(path.Join(dir2, Assets().filenameStationPubkey))
	os.Remove(dir1)
	os.Remove(dir2)
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

func TestAssetsEmptyClientConf(t *testing.T) {
	log.SetOutput(io.Discard)
	defer log.SetOutput(os.Stdout)

	dir := t.TempDir()
	err := copyFile(conjurepath.Root+"/internal/test_assets/ClientConf", dir+"/ClientConf")
	require.Nil(t, err)

	// ====[ ClientConf file is empty ]=====
	_, err = AssetsSetDir(dir)
	require.Nil(t, err)

	C := Assets().GetClientConfPtr()

	// create temporary ClientConf file in temp test Dir
	dir2 := t.TempDir()

	// Error occurs while updating assets dir, clientconf remains unchanged from
	// default from initialization.
	_, err = AssetsSetDir(dir2)
	require.NotNil(t, err)
	require.ErrorIs(t, err, syscall.ENOENT)

	// ClientConf remains unchanged
	require.Equal(t, C, Assets().GetClientConfPtr())

	// However, the path in the assets is updated.
	require.Equal(t, Assets().path, dir2)
}
