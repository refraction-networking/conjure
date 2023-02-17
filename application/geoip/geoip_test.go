package geoip

import (
	"net"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func DisabledTestGeoIPMaxMind(t *testing.T) {
	dbDir := "/opt/mmdb/"
	c := &DBConfig{
		ASNDBPath: filepath.Join(dbDir, "GeoLite2-ASN.mmdb"),
		CCDBPath:  filepath.Join(dbDir, "GeoLite2-Country.mmdb"),
	}

	db, err := New(c)
	require.Nil(t, err)

	// If you are using strings that may be invalid, check that ip is not nil
	ip := net.ParseIP("81.2.69.142")
	cc, err := db.CC(ip)
	require.Nil(t, err)

	asn, err := db.ASN(ip)
	require.Nil(t, err)

	t.Log(cc)
	t.Log(asn)
}

func DisabledTestGeoIPNoASN(t *testing.T) {
	dbDir := "/opt/mmdb/"
	c := &DBConfig{
		CCDBPath: filepath.Join(dbDir, "GeoLite2-Country.mmdb"),
	}

	db, err := New(c)
	require.ErrorIs(t, err, ErrMissingDB)
	require.NotNil(t, db)

	// If you are using strings that may be invalid, check that ip is not nil
	ip := net.ParseIP("81.2.69.142")
	cc, err := db.CC(ip)
	require.Nil(t, err)
	require.Equal(t, "GB", cc)

	asn, err := db.ASN(ip)
	require.Nil(t, err)
	require.Equal(t, uint(0), asn)
}

func DisabledTestGeoIPNoCC(t *testing.T) {
	dbDir := "/opt/mmdb/"
	c := &DBConfig{
		ASNDBPath: filepath.Join(dbDir, "GeoLite2-ASN.mmdb"),
		CCDBPath:  "",
	}

	db, err := New(c)
	require.ErrorIs(t, err, ErrMissingDB)
	require.NotNil(t, db)

	// If you are using strings that may be invalid, check that ip is not nil
	ip := net.ParseIP("81.2.69.142")
	cc, err := db.CC(ip)
	require.Nil(t, err)
	require.Equal(t, "", cc)

	asn, err := db.ASN(ip)
	require.Nil(t, err)
	require.Equal(t, uint(20712), asn)
}

func TestGeoIPEmpty(t *testing.T) {
	c := &DBConfig{
		ASNDBPath: "",
		CCDBPath:  "",
	}

	_, err := New(nil)
	require.ErrorIs(t, err, ErrMissingDB)

	db, err := New(c)
	require.ErrorIs(t, err, ErrMissingDB)
	require.NotNil(t, db)

	// If you are using strings that may be invalid, check that ip is not nil
	ip := net.ParseIP("81.2.69.142")
	cc, err := db.CC(ip)
	require.Nil(t, err)
	require.Equal(t, "", cc)

	asn, err := db.ASN(ip)
	require.Nil(t, err)
	require.Equal(t, uint(0), asn)
}

func TestGeoIPNonMissingError(t *testing.T) {
	c := &DBConfig{
		ASNDBPath: "",
		CCDBPath:  "abcdef",
	}

	db, err := New(c)
	require.NotErrorIs(t, err, ErrMissingDB)
	require.Nil(t, db)
}
