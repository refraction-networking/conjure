package transports

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/refraction-networking/gotapdance/ed25519"
	"github.com/refraction-networking/gotapdance/ed25519/extra25519"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/curve25519"
)

func TestObfuscateRevealIntended(t *testing.T) {
	_, private, _ := ed25519.GenerateKey(rand.Reader)

	var curve25519Public, curve25519Private [32]byte
	extra25519.PrivateKeyToCurve25519(&curve25519Private, private)
	curve25519.ScalarBaseMult(&curve25519Public, &curve25519Private)

	buf := make([]byte, 32)
	_, err := rand.Read(buf)
	require.Nil(t, err)

	for _, Obfsc := range []Obfuscator{GCMObfuscator{}, CTRObfuscator{}, NilObfuscator{}} {
		ciphertext, err := Obfsc.Obfuscate(buf, curve25519Public[:])
		require.Nil(t, err)

		plaintext, err := Obfsc.TryReveal(ciphertext, curve25519Private)
		require.Nil(t, err)

		require.NotEmpty(t, plaintext)
		require.True(t, bytes.Equal(buf, plaintext))
	}
}

func TestObfuscateReveal1B(t *testing.T) {
	_, private, _ := ed25519.GenerateKey(rand.Reader)

	var curve25519Public, curve25519Private [32]byte
	extra25519.PrivateKeyToCurve25519(&curve25519Private, private)
	curve25519.ScalarBaseMult(&curve25519Public, &curve25519Private)

	for _, Obfsc := range []Obfuscator{GCMObfuscator{}, CTRObfuscator{}, NilObfuscator{}} {
		ciphertext, err := Obfsc.Obfuscate([]byte{0xff}, curve25519Public[:])
		require.Nil(t, err)

		plaintext, err := Obfsc.TryReveal(ciphertext, curve25519Private)
		require.Nil(t, err)

		require.NotEmpty(t, plaintext)
		// t.Log(len(ciphertext))
		require.True(t, bytes.Equal([]byte{0xff}, plaintext))
	}
}

func TestObfuscateReveal100B(t *testing.T) {
	_, private, _ := ed25519.GenerateKey(rand.Reader)

	var curve25519Public, curve25519Private [32]byte
	extra25519.PrivateKeyToCurve25519(&curve25519Private, private)
	curve25519.ScalarBaseMult(&curve25519Public, &curve25519Private)

	buf := make([]byte, 100)
	_, err := rand.Read(buf)
	require.Nil(t, err)

	for _, Obfsc := range []Obfuscator{GCMObfuscator{}, CTRObfuscator{}, NilObfuscator{}} {
		ciphertext, err := Obfsc.Obfuscate(buf, curve25519Public[:])
		require.Nil(t, err)

		plaintext, err := Obfsc.TryReveal(ciphertext, curve25519Private)
		require.Nil(t, err)

		require.NotEmpty(t, plaintext)
		require.True(t, bytes.Equal(buf, plaintext))
	}
}
