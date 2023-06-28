package core

import (
	"crypto/hmac"
	"crypto/sha256"
)

// ConjureHMAC implements the hmak that can then be used for further hkdf key generation
func ConjureHMAC(key []byte, str string) []byte {
	hash := hmac.New(sha256.New, key)
	hash.Write([]byte(str))
	return hash.Sum(nil)
}
