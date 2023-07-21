package utls

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"fmt"
	"io"
	"math/big"
	"time"

	tls "github.com/refraction-networking/utls"
	"golang.org/x/crypto/hkdf"
)

func publicKey(priv any) any {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	case ed25519.PrivateKey:
		return k.Public().(ed25519.PublicKey)
	default:
		return nil
	}
}

func genKey(r io.Reader, ecdsaCurve string, ed25519Key bool, rsaBits int) (priv any, err error) {
	switch ecdsaCurve {
	case "":
		if ed25519Key {
			_, priv, err = ed25519.GenerateKey(r)
		} else {
			priv, err = rsa.GenerateKey(r, rsaBits)
		}
	case "P224":
		priv, err = ecdsa.GenerateKey(elliptic.P224(), r)
	case "P256":
		priv, err = ecdsa.GenerateKey(elliptic.P256(), r)
	case "P384":
		priv, err = ecdsa.GenerateKey(elliptic.P384(), r)
	case "P521":
		priv, err = ecdsa.GenerateKey(elliptic.P521(), r)
	default:
		err = fmt.Errorf("Unrecognized elliptic curve: %q", ecdsaCurve)
	}
	if err != nil {
		err = fmt.Errorf("Failed to generate private key: %v", err)
	}
	return
}

type not1Reader struct {
	r io.Reader
}

func (n1r *not1Reader) Read(p []byte) (n int, err error) {

	if len(p) == 1 {
		// err = io.EOF
		return 1, nil
	}

	return n1r.r.Read(p)
}

// func clientHelloRandomFromSeed(seed []byte) ([handshake.RandomBytesLength]byte, error) {
// 	randSource := hkdf.New(sha256.New, seed, nil, nil)
// 	randomBytes := [handshake.RandomBytesLength]byte{}

// 	_, err := io.ReadFull(randSource, randomBytes[:])
// 	if err != nil {
// 		return [handshake.RandomBytesLength]byte{}, err
// 	}

// 	return randomBytes, nil
// }

// getPrivkey creates ECDSA private key used in DTLS Certificates
func getPrivkey(seed []byte) (*ecdsa.PrivateKey, error) {
	randSource := hkdf.New(sha256.New, seed, nil, nil)

	privkey, err := ecdsa.GenerateKey(elliptic.P256(), &not1Reader{r: randSource})
	if err != nil {
		return &ecdsa.PrivateKey{}, err
	}
	return privkey, nil
}

// getX509Tpl creates x509 template for x509 Certificates generation used in DTLS Certificates.
func getX509Tpl(seed []byte) (*x509.Certificate, error) {
	randSource := hkdf.New(sha256.New, seed, nil, nil)

	maxBigInt := new(big.Int)
	maxBigInt.Exp(big.NewInt(2), big.NewInt(130), nil).Sub(maxBigInt, big.NewInt(1))
	serialNumber, err := rand.Int(randSource, maxBigInt)
	if err != nil {
		return &x509.Certificate{}, err
	}

	// Make the Certificate valid from UTC today till next month.
	utcNow := time.Now().UTC()
	validFrom := time.Date(utcNow.Year(), utcNow.Month(), utcNow.Day(), 0, 0, 0, 0, time.UTC)
	validUntil := validFrom.AddDate(0, 1, 0)

	// random CN
	cnBytes := make([]byte, 8)
	_, err = io.ReadFull(randSource, cnBytes)
	if err != nil {
		return &x509.Certificate{}, fmt.Errorf("failed to generate common name: %w", err)
	}
	cn := hex.EncodeToString(cnBytes)

	return &x509.Certificate{
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
			x509.ExtKeyUsageServerAuth,
		},
		BasicConstraintsValid: true,
		NotBefore:             validFrom,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		NotAfter:              validUntil,
		SerialNumber:          serialNumber,
		SignatureAlgorithm:    x509.ECDSAWithSHA256,
		Version:               2,
		Subject:               pkix.Name{CommonName: cn},
		DNSNames:              []string{cn},
		IsCA:                  true,
	}, nil
}

func newCertificate(seed []byte) (*tls.Certificate, error) {
	privkey, err := getPrivkey(seed)
	if err != nil {
		return &tls.Certificate{}, err
	}

	tpl, err := getX509Tpl(seed)
	if err != nil {
		return &tls.Certificate{}, err
	}

	randSource := hkdf.New(sha256.New, seed, nil, nil)

	certDER, err := x509.CreateCertificate(randSource, tpl, tpl, privkey.Public(), privkey)
	if err != nil {
		return &tls.Certificate{}, err
	}

	return &tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  privkey,
	}, nil
}

func buildSymmetricVerifier(psk []byte) func(cs tls.ConnectionState) error {
	return func(cs tls.ConnectionState) error {
		expected, err := newCertificate(psk)
		// expected.Leaf.KeyUsage |= x509.KeyUsageCertSign

		if !cs.DidResume {
			return fmt.Errorf("expected session resumption")
		}

		if len(cs.PeerCertificates) != 1 {
			return fmt.Errorf("expected 1 peer certificate, got %v", len(cs.PeerCertificates))
		}

		if len(expected.Certificate) != 1 {
			return fmt.Errorf("expected 1 pre-established cert, got %v", len(expected.Certificate))
		}

		expectedCert, err := x509.ParseCertificate(expected.Certificate[0])
		if err != nil {
			return fmt.Errorf("error parsing peer certificate: %v", err)
		}

		err = verifyCert(cs.PeerCertificates[0], expectedCert)
		if err != nil {
			return fmt.Errorf("error verifying peer certificate: %v", err)
		}

		return nil
	}
}

func verifyCert(incoming, correct *x509.Certificate) error {
	correct.KeyUsage |= x509.KeyUsageCertSign // CheckSignature have requirements for the KeyUsage field
	err := incoming.CheckSignatureFrom(correct)
	if err != nil {
		return fmt.Errorf("error verifying certificate signature: %v", err)
	}

	return nil
}
