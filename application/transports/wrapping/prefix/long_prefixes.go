package prefix

import "encoding/hex"

var httpGetComplete []byte = d("")

var tlsCompleteCHSNI []byte = d("")

var tlsCompleteCHNoSNI []byte = d("")

func d(in string) []byte {

	out, err := hex.DecodeString(in)
	if err != nil {
		panic(err)
	}
	return out
}
