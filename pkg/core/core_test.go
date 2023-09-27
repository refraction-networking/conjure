package core

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/hkdf"

	pb "github.com/refraction-networking/conjure/proto"
)

func TestNewGenKeys(t *testing.T) {
	var fakePubkey [32]byte
	k, _ := hex.DecodeString("00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF")
	copy(fakePubkey[:], k)

	keys, err := GenerateClientSharedKeys(fakePubkey)
	require.Nil(t, err)
	oldKeys, err := generateClientSharedKeysOld(fakePubkey)
	require.Nil(t, err)

	stationKeys, err := GenSharedKeys(4, keys.SharedSecret, pb.TransportType_Null)
	require.Nil(t, err)
	stationKeysOld, err := GenSharedKeys(3, oldKeys.SharedSecret, pb.TransportType_Null)
	require.Nil(t, err)

	if !bytes.Equal(keys.ConjureSeed, stationKeys.ConjureSeed) {
		t.Fatalf("Version 4 station ConjureSeed does not match client: \nStation: %v\nClient: %v", stationKeys.ConjureSeed, keys.ConjureSeed)
	}

	if !bytes.Equal(oldKeys.ConjureSeed, stationKeysOld.ConjureSeed) {
		t.Fatalf("Version 3 station ConjureSeed does not match client: \nStation: %v\nClient: %v", stationKeysOld.ConjureSeed, oldKeys.ConjureSeed)
	}
}

// Below is for testing that SharedSecret and ConjureSeed match with old client version.
type oldSharedKeys struct {
	SharedSecret, Representative                               []byte
	FspKey, FspIv, VspKey, VspIv, NewMasterSecret, ConjureSeed []byte
	reader                                                     io.Reader
}

func generateClientSharedKeysOld(pubkey [32]byte) (*oldSharedKeys, error) {
	sharedSecret, representative, err := generateEligatorTransformedKey(pubkey[:])
	if err != nil {
		return nil, err
	}

	tdHkdf := hkdf.New(sha256.New, sharedSecret, []byte("conjureconjureconjureconjure"), nil)
	keys := &oldSharedKeys{
		SharedSecret:    sharedSecret,
		Representative:  representative,
		FspKey:          make([]byte, 16),
		FspIv:           make([]byte, 12),
		VspKey:          make([]byte, 16),
		VspIv:           make([]byte, 12),
		NewMasterSecret: make([]byte, 48),
		ConjureSeed:     make([]byte, 16),
		reader:          tdHkdf,
	}

	if _, err := tdHkdf.Read(keys.FspKey); err != nil {
		return keys, err
	}
	if _, err := tdHkdf.Read(keys.FspIv); err != nil {
		return keys, err
	}
	if _, err := tdHkdf.Read(keys.VspKey); err != nil {
		return keys, err
	}
	if _, err := tdHkdf.Read(keys.VspIv); err != nil {
		return keys, err
	}
	if _, err := tdHkdf.Read(keys.NewMasterSecret); err != nil {
		return keys, err
	}
	if _, err := tdHkdf.Read(keys.ConjureSeed); err != nil {
		return keys, err
	}
	return keys, err
}
