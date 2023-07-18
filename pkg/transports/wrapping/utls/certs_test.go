package utls

import (
	"crypto/rand"
	"reflect"
	"testing"
)

func Test_generateKeyAndCert(t *testing.T) {
	type args struct {
		secret [32]byte
		names  []string
	}
	tests := []struct {
		name    string
		args    args
		want    []byte
		want1   []byte
		wantErr bool
	}{
		{
			"basic cert and key generation",
			args{
				secret: [32]byte{},
				names:  []string{"localhost"},
			},
			[]byte{},
			[]byte{},
			false,
		},
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, got1, err := generateKeyAndCert(rand.Reader, tt.args.secret, tt.args.names)
			if (err != nil) != tt.wantErr {
				t.Errorf("generateKeyAndCert() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("generateKeyAndCert() got = %v, want %v", got, tt.want)
			}
			if !reflect.DeepEqual(got1, tt.want1) {
				t.Errorf("generateKeyAndCert() got1 = %v, want %v", got1, tt.want1)
			}
		})
	}
}
