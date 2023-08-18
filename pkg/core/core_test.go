package core

import (
	"bytes"
	"crypto/sha256"
	"io"
	"testing"

	pb "github.com/refraction-networking/conjure/proto"

	"golang.org/x/crypto/hkdf"
)

func TestNewGenKeys(t *testing.T) {
	fakePubkey := [32]byte{0}

	keys, _ := GenerateClientSharedKeys(fakePubkey)
	oldKeys, _ := generateClientSharedKeysOld(fakePubkey)

	stationKeys, _ := GenSharedKeys(4, keys.SharedSecret, pb.TransportType_Null)
	stationKeysOld, _ := GenSharedKeys(3, oldKeys.SharedSecret, pb.TransportType_Null)

	if !bytes.Equal(keys.ConjureSeed, stationKeys.ConjureSeed) {
		t.Fatalf("Version 4 station ConjureSeed does not match client: \nStation: %v\nClient: %v", stationKeys.ConjureSeed, keys.ConjureSeed)
	}

	if !bytes.Equal(oldKeys.ConjureSeed, stationKeysOld.ConjureSeed) {
		t.Fatalf("Version 3 station ConjureSeed does not match client: \nStation: %v\nClient: %v", stationKeysOld.ConjureSeed, oldKeys.ConjureSeed)
	}
}

// Below is for testing that SharedSecret and ConjureSeed match with old client version.
type OldSharedKeys struct {
	SharedSecret, Representative                               []byte
	FspKey, FspIv, VspKey, VspIv, NewMasterSecret, ConjureSeed []byte
	reader                                                     io.Reader
}

// oldConjureSharedKeys contains keys that the station is required to keep.
type oldConjureSharedKeys struct {
	SharedSecret                                            []byte
	FspKey, FspIv, VspKey, VspIv, MasterSecret, ConjureSeed []byte
}

func generateClientSharedKeysOld(pubkey [32]byte) (*OldSharedKeys, error) {
	sharedSecret, representative, err := generateEligatorTransformedKey(pubkey[:])
	if err != nil {
		return nil, err
	}

	tdHkdf := hkdf.New(sha256.New, sharedSecret, []byte("conjureconjureconjureconjure"), nil)
	keys := &OldSharedKeys{
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
