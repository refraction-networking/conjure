package overrides

import (
	"bytes"
	"encoding/hex"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

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
		exPort int
		rr     io.Reader
	}{
		{"single prefix", "1000 10 0x21 80 HTT", "HTT", true, 80, rr},
		{"no port override", "1000 10 0x22 -1 Foo", "Foo", true, -1, rr},
		{"guaranteed selection equal", "1 1 0x22 -1 Foo", "Foo", true, -1, rr},
		{"guaranteed selection over", "1 3 0x22 -1 Foo", "Foo", true, -1, rr},
		{"guaranteed non-selection", "1 0 0x22 -1 Foo", "", false, -1, rr},
		{"two prefixes select first", "1000 10 0x21 80 HTT\n1000 10 0x22 22 SSH", "HTT", true, 80, rr},
		{"two prefixes select second", "1000 10 0x21 80 HTT\n1000 10 0x22 22 SSH", "SSH", true, 22, bytes.NewReader(d("0100000"))},
	}

	for _, tt := range tests {
		t.Run(tt.descr, func(t *testing.T) {
			r := strings.NewReader(tt.input)
			prefs, err := ParsePrefixes(r)
			require.Nil(t, err)

			require.NotNil(t, prefs)

			p, ok := prefs.prefixes.selectPrefix(tt.rr, nil)
			require.Equal(t, tt.exOk, ok)
			if !ok {
				require.Nil(t, p)
				return
			}
			require.Equal(t, tt.exPref, string(p.prefix))
			require.Equal(t, tt.exPort, p.port)
		})
		rr.Seek(0, io.SeekStart)
	}
}
