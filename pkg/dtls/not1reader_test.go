package dtls

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFakeReader(t *testing.T) {
	msg := "test byte string for read"

	n1r := &Not1Reader{
		r: bytes.NewReader([]byte(msg)),
	}

	var buf1 [1]byte
	n, err := n1r.Read(buf1[:])
	require.Nil(t, err)
	require.Equal(t, 1, n)

	buf := make([]byte, len(msg))
	n, err = n1r.Read(buf)
	require.Nil(t, err)
	require.Equal(t, len(msg), n)
	require.Equal(t, msg, string(buf))
}
