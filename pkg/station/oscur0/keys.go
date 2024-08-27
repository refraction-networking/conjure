package oscur0

import (
	"encoding/hex"
	"fmt"
)

func sliceToArray(key []byte) ([privkeylen]byte, error) {
	if len(key) != privkeylen {
		return [privkeylen]byte{}, fmt.Errorf("length of key is %v, must be %v", len(key), privkeylen)
	}

	key32Bytes := [privkeylen]byte{}
	copy(key32Bytes[:], key)
	return key32Bytes, nil
}

func decodeStringKey(key string) ([privkeylen]byte, error) {
	keyBytes, err := hex.DecodeString(key)
	if err != nil {
		return [privkeylen]byte{}, fmt.Errorf("error decoding hex key string: %v", err)
	}

	return sliceToArray(keyBytes)
}
