package lib

import (
	"crypto/sha256"

	"golang.org/x/crypto/hkdf"
)

type ConjureSharedKeys struct {
	representative                                            []byte
	FspKey, FspIv, VspKey, VspIv, MasterSecret, DarkDecoySeed []byte
}

func GenSharedKeys(representative []byte) (ConjureSharedKeys, error) {
	tdHkdf := hkdf.New(sha256.New, representative, []byte("tapdancetapdancetapdancetapdance"), nil)
	keys := ConjureSharedKeys{
		representative: representative,
		FspKey:         make([]byte, 16),
		FspIv:          make([]byte, 12),
		VspKey:         make([]byte, 16),
		VspIv:          make([]byte, 12),
		MasterSecret:   make([]byte, 48),
		DarkDecoySeed:  make([]byte, 16),
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
	if _, err := tdHkdf.Read(keys.DarkDecoySeed); err != nil {
		return keys, err
	}
	return keys, nil
}
