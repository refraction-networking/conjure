package overrides

import (
	"bytes"
	"encoding/hex"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestOverrideParsePrefix(t *testing.T) {

	text := `100 67 0x01 80 "GET / HTTP/1.1\r\n"
	1000 10 0x21 80 "HTT"
	1000 10 0x22 -1 "amweoafimdoifavwe"
	`
	r := strings.NewReader(text)
	prefs, err := ParsePrefixes(r)
	require.Nil(t, err)

	require.NotNil(t, prefs)
}

func TestOverrideNewPrefix(t *testing.T) {
	np, err := NewPrefixTransportOverride("")
	require.Nil(t, err)
	require.Nil(t, np)
}

func TestOverrideSelectPrefix(t *testing.T) {

	d := func(s string) []byte {
		x, _ := hex.DecodeString(s)
		return x
	}

	notRand := d("000000")
	rr := bytes.NewReader(notRand)

	var tests = []struct {
		descr  string
		input  string
		exPref string
		exOk   bool
		rr     io.Reader
	}{
		{"single prefix", "1000 10 0x21 80 HTT", "HTT", true, rr},
		{"no port override", "1000 10 0x22 -1 Foo", "Foo", true, rr},
		{"guaranteed selection equal", "1 1 0x22 -1 Foo", "Foo", true, rr},
		{"guaranteed selection over", "1 3 0x22 -1 Foo", "Foo", true, rr},
		{"guaranteed non-selection", "1 0 0x22 -1 Foo", "", false, rr},
		{"two prefixes select first", "1000 10 0x21 80 HTT\n1000 10 0x22 80 SSH", "HTT", true, rr},
		{"two prefixes select second", "1000 10 0x21 80 HTT\n1000 10 0x22 80 SSH", "SSH", true, bytes.NewReader(d("0100000"))},
	}

	for _, tt := range tests {
		t.Run(tt.descr, func(t *testing.T) {
			r := strings.NewReader(tt.input)
			prefs, err := ParsePrefixes(r)
			require.Nil(t, err)

			require.NotNil(t, prefs)

			p, ok := prefs.selectPrefix(tt.rr, nil)
			require.Equal(t, tt.exOk, ok)
			require.Equal(t, tt.exPref, string(p))
		})
		rr.Seek(0, io.SeekStart)
	}
}
