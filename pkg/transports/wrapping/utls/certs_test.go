package utls

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"testing"

	"golang.org/x/crypto/hkdf"
)

func Test_generateKeyAndCert(t *testing.T) {
	type args struct {
		secret [32]byte
		names  []string
	}
	tests := []struct {
		name    string
		args    args
		wantErr bool
	}{
		{
			"basic cert and key generation",
			args{
				secret: [32]byte{},
				names:  []string{"localhost"},
			},
			false,
		},
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := readerFromKey(tt.args.secret)
			_, _, err := generateKeyAndCert(reader, tt.args.secret, tt.args.names)
			if (err != nil) != tt.wantErr {
				t.Errorf("generateKeyAndCert() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
		})
	}
}

func readerFromKey(key [32]byte) io.Reader {
	hkdfReader := hkdf.New(sha256.New, key[:], []byte("cert testing string"), nil)
	return hkdfReader
}

func fromString(s string) []byte {
	b, e := hex.DecodeString(s)
	if e != nil {
		panic(e)
	}
	return b
}
