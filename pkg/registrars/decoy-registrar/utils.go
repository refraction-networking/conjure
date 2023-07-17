package decoy

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	mrand "math/rand"
	"time"
)

// The key argument should be the AES key, either 16 or 32 bytes
// to select AES-128 or AES-256.
func aesGcmEncrypt(plaintext []byte, key []byte, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesGcmCipher, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return aesGcmCipher.Seal(nil, iv, plaintext, nil), nil
}

// Tries to get crypto random int in range [min, max]
// In case of crypto failure -- return insecure pseudorandom
func getRandInt(min int, max int) int {
	// I can't believe Golang is making me do that
	// Flashback to awful C/C++ libraries
	diff := max - min
	if diff < 0 {
		// r.logger.Warningf("getRandInt(): max is less than min")
		min = max
		diff *= -1
	} else if diff == 0 {
		return min
	}
	var v int64
	err := binary.Read(rand.Reader, binary.LittleEndian, &v)
	if v < 0 {
		v *= -1
	}
	if err != nil {
		// r.logger.Warningf("Unable to securely get getRandInt(): " + err.Error())
		v = mrand.Int63()
	}
	return min + int(v%int64(diff+1))
}

// returns random duration between min and max in milliseconds
func getRandomDuration(min int, max int) time.Duration {
	return time.Millisecond * time.Duration(getRandInt(min, max))
}

// Converts provided duration to raw milliseconds.
// Returns a pointer to u32, because protobuf wants pointers.
// Max valid input duration (that fits into uint32): 49.71 days.
func durationToU32ptrMs(d time.Duration) *uint32 {
	i := uint32(d.Nanoseconds() / int64(time.Millisecond))
	return &i
}

func rttInt(millis uint32) int {
	defaultValue := 300
	if millis == 0 {
		return defaultValue
	}
	return int(millis)
}
