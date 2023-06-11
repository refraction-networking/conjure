package overrides

import (
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
	prefs, err := parsePrefixes(r)
	require.Nil(t, err)

	require.NotNil(t, prefs)
}

func TestOverrideNewPrefix(t *testing.T) {
	np, err := NewPrefixTransportOverride("")
	require.Nil(t, err)
	require.Nil(t, np)
}

func TestOverrideSelectPrefix(t *testing.T) {

	text := `1000 10 0x21 80 "HTT"`
	r := strings.NewReader(text)
	prefs, err := parsePrefixes(r)
	require.Nil(t, err)

	require.NotNil(t, prefs)

	_, ok := prefs.selectPrefix(nil, nil)
	require.True(t, ok)
}
