package lib

import (
	"crypto/hmac"
	"crypto/sha256"
	"io"

	"gitlab.com/yawning/obfs4.git/common/ntor"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"

	pb "github.com/refraction-networking/gotapdance/protobuf"
)

type Obfs4Keys struct {
	PrivateKey *ntor.PrivateKey
	PublicKey  *ntor.PublicKey
	NodeID     *ntor.NodeID
}

func generateObfs4Keys(rand io.Reader) (Obfs4Keys, error) {
	keys := Obfs4Keys{
		PrivateKey: new(ntor.PrivateKey),
		PublicKey:  new(ntor.PublicKey),
		NodeID:     new(ntor.NodeID),
	}

	_, err := rand.Read(keys.PrivateKey[:])
	if err != nil {
		return keys, err
	}

	keys.PrivateKey[0] &= 248
	keys.PrivateKey[31] &= 127
	keys.PrivateKey[31] |= 64

	pub, err := curve25519.X25519(keys.PrivateKey[:], curve25519.Basepoint)
	if err != nil {
		return keys, err
	}
	copy(keys.PublicKey[:], pub)

	_, err = rand.Read(keys.NodeID[:])
	return keys, err
}

type ConjureSharedKeys struct {
	SharedSecret                                            []byte
	FspKey, FspIv, VspKey, VspIv, MasterSecret, ConjureSeed []byte
	Obfs4Keys                                               Obfs4Keys
}

func GenSharedKeys(sharedSecret []byte, tt pb.TransportType) (ConjureSharedKeys, error) {
	tdHkdf := hkdf.New(sha256.New, sharedSecret, []byte("conjureconjureconjureconjure"), nil)
	keys := ConjureSharedKeys{
		SharedSecret: sharedSecret,
		FspKey:       make([]byte, 16),
		FspIv:        make([]byte, 12),
		VspKey:       make([]byte, 16),
		VspIv:        make([]byte, 12),
		MasterSecret: make([]byte, 48),
		ConjureSeed:  make([]byte, 16),
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
	if _, err := tdHkdf.Read(keys.MasterSecret); err != nil {
		return keys, err
	}
	if _, err := tdHkdf.Read(keys.ConjureSeed); err != nil {
		return keys, err
	}

	var err error
	if tt == pb.TransportType_Obfs4 {
		keys.Obfs4Keys, err = generateObfs4Keys(tdHkdf)
	}
	return keys, err
}

// from client tapdance/conjure.go
func conjureHMAC(key []byte, str string) []byte {
	hash := hmac.New(sha256.New, key)
	hash.Write([]byte(str))
	return hash.Sum(nil)
}

func (k *ConjureSharedKeys) ConjureHMAC(str string) []byte {
	return conjureHMAC(k.SharedSecret, str)
}
