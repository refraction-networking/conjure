package lib

import (
	"crypto/sha256"
	"io"

	"gitlab.com/yawning/obfs4.git/common/ntor"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/hkdf"

	pb "github.com/refraction-networking/conjure/proto"
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

// ConjureSharedKeys contains keys that the station is required to keep.
type ConjureSharedKeys struct {
	SharedSecret []byte
	ConjureSeed  []byte
	Obfs4Keys    Obfs4Keys
}

// GenSharedKeys generates the keys requires to form a Conjure connection based on the SharedSecret
func GenSharedKeys(clientLibVer uint, sharedSecret []byte, tt pb.TransportType) (ConjureSharedKeys, error) {
	tdHkdf := hkdf.New(sha256.New, sharedSecret, []byte("conjureconjureconjureconjure"), nil)
	keys := ConjureSharedKeys{
		SharedSecret: sharedSecret,
		ConjureSeed:  make([]byte, 16),
	}

	// To maintain compatability with old client version, ensure the same number of random bytes are read before reading ConjureSeed
	if clientLibVer < 4 {
		emptyBuf := make([]byte, 16+12+16+12+48)
		tdHkdf.Read(emptyBuf)
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
