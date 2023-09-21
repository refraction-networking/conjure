package client

import (
	"context"
	"crypto/hmac"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"syscall"
	"testing"

	"github.com/refraction-networking/conjure/pkg/client/assets"
	"github.com/refraction-networking/conjure/pkg/core"
	"github.com/refraction-networking/conjure/pkg/log"
	"github.com/refraction-networking/conjure/pkg/phantoms"
	pb "github.com/refraction-networking/conjure/proto"
	tls "github.com/refraction-networking/utls"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTLSFailure(t *testing.T) {

	testUrls := map[string]string{
		"expiredTlsUrl":       "expired.badssl.com", // x509: certificate has expired or is not yet valid
		"wrongHostTlsUrl":     "wrong.host.badssl.com",
		"untrustedRootTlsUrl": "untrusted-root.badssl.com",
		"revokedTlsUrl":       "revoked.badssl.com",
		"pinningTlsUrl":       "pinning-test.badssl.com",
	}

	simpleRequest := "GET / HTTP/1.1\r\nHOST:%s\r\n\r\n"

	for issue, url := range testUrls {

		dialConn, err := net.Dial("tcp", url+":443")
		if err != nil {
			t.Fatalf("Failed when we shouldn't have: %v", err)
		}
		defer dialConn.Close()

		config := tls.Config{ServerName: url}
		tlsConn := tls.UClient(dialConn, &config, tls.HelloChrome_62)
		defer tlsConn.Close()

		request := fmt.Sprintf(simpleRequest, url)

		_, err = tlsConn.Write([]byte(request))
		if err != nil {
			t.Logf("%v - %v: [%v]", issue, url, err)
		} else {
			t.Logf("%v - %v: <no issue>", issue, url)
		}
	}

}

func TestSelectBoth(t *testing.T) {
	seed := []byte{
		0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7,
		0x8, 0x9, 0xA, 0xB, 0xC, 0xD, 0xE, 0xF,
	}

	phantomIPAddr4, phantomIPAddr6, _, err := SelectPhantom(seed, V4|V6)
	require.Nil(t, err, "encountered err while selecting IPs")
	require.NotNil(t, phantomIPAddr4, "Failed to select IPv4 address (support: both")
	require.Equal(t, "192.122.190.252", phantomIPAddr4.String(), "Incorrect Address chosen")
	require.NotNil(t, phantomIPAddr6, "Failed to select IPv6 address (support: both")
	require.Equal(t, "2001:48a8:687f:1:fc9d:ee40:b05d:6656", phantomIPAddr6.String(), "Incorrect Address chosen")
}

func TestConjureHMAC(t *testing.T) {
	// generated using
	// echo "customString" | hmac256 "1abcd2efgh3ijkl4"
	// soln1Str := "d209c99ea22606e5b990a770247b0cd005c157208cb7194fef407fe3fa7e9266"
	soln1Str := "d10b84f9e2cc57bb4294b8929a3fca25cce7f95eb226fa5bcddc5417e1d2eac2"

	soln1 := make([]byte, hex.DecodedLen(len(soln1Str)))
	_, e := hex.Decode(soln1, []byte(soln1Str))
	require.Nil(t, e, "Failed to decode hex string")

	test1 := core.ConjureHMAC([]byte("1abcd2efgh3ijkl4"), "customString")
	test1Str := make([]byte, hex.EncodedLen(len(test1)))
	hex.Encode(test1Str, test1)

	if len(test1) != len(soln1) {
		t.Fatalf("Wrong hash Length:\n%s\n%s", soln1Str, test1Str)
	}

	if !hmac.Equal(test1, soln1) {
		t.Fatalf("Wrong hash returned:\n%s\n%s", soln1Str, test1Str)
	}
}

func TestGenerateKeys(t *testing.T) {
	var fakePubkey [32]byte
	k, _ := hex.DecodeString("00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF")
	copy(fakePubkey[:], k)
	keys, err := core.GenerateClientSharedKeys(fakePubkey)
	if err != nil {
		t.Fatalf("Failed to generate Conjure Keys: %v", err)
	}
	if keys == nil {
		t.Fatalf("Incorrect Keys generated: %v", keys.SharedSecret)
	}
}

func TestRegDigest(t *testing.T) {
	reg := ConjureReg{ConjureSession: &ConjureSession{}}
	soln1 := "{result:\"no stats tracked\"}"

	if reg.digestStats() != soln1 {
		t.Fatalf("Incorrect stats digest returned")
	}

	testRTT := uint32(1000)
	reg.stats = &pb.SessionStats{
		TotalTimeToConnect: &testRTT,
		TcpToDecoy:         &testRTT}

	soln2 := "{result:\"success\", tcp_to_decoy:1000, tls_to_decoy:0, total_time_to_connect:1000}"
	if reg.digestStats() != soln2 {
		t.Fatalf("Incorrect stats digest returned")
	}

	reg.stats.TlsToDecoy = &testRTT

	soln3 := "{result:\"success\", tcp_to_decoy:1000, tls_to_decoy:1000, total_time_to_connect:1000}"
	if reg.digestStats() != soln3 {
		t.Fatalf("Incorrect stats digest returned")
	}
}

func TestCheckV6Decoys(t *testing.T) {
	_, err := assets.AssetsSetDir("./assets")
	require.ErrorIs(t, err, syscall.ENOENT) // ignore assets not found - expected

	decoysV6 := assets.Assets().GetV6Decoys()
	numDecoys := len(decoysV6)

	for _, decoy := range decoysV6 {
		if decoy.Ipv4Addr != nil {
			// If a decoys Ipv4 address is defined it will ignore the IPv6 address
			numDecoys--
		}
	}

	// t.Logf("V6 Decoys: %v", numDecoys)
	// if numDecoys < 5 {
	// 	t.Fatalf("Not enough V6 decoys in ClientConf (has: %v, need at least: %v)", numDecoys, 5)
	// }
}

func TestGetFirstConnection(t *testing.T) {
	type params struct {
		ips     []*net.IP
		dialErr error
		retErr  error
	}

	ip1 := net.IPv4(1, 1, 1, 1)
	ip2 := net.IPv6loopback

	testCases := []params{
		{nil, nil, ErrNoOpenConns},
		{[]*net.IP{}, nil, ErrNoOpenConns},
		{[]*net.IP{&ip1}, nil, nil},
		{[]*net.IP{nil}, nil, ErrNoOpenConns},
		{[]*net.IP{&ip1, &ip1}, nil, nil},
		{[]*net.IP{&ip1, &ip2}, nil, nil},
		{[]*net.IP{&ip2, &ip1}, nil, nil},
		{[]*net.IP{&ip2, &ip2}, nil, nil},
		{[]*net.IP{&ip1, nil}, nil, nil},
		{[]*net.IP{nil, &ip1}, nil, nil},
		{[]*net.IP{&ip2, nil}, nil, nil},
	}

	for i, c := range testCases {
		testGetFirstConn(t, c.ips, c.dialErr, c.retErr, i)
	}
}

func testGetFirstConn(t *testing.T, addrList []*net.IP, dialErr error, retErr error, i int) {
	reg := ConjureReg{
		ConjureSession: &ConjureSession{},
		phantomDstPort: 443,
	}

	cl, _ := net.Pipe()
	defer cl.Close()

	dialFn := func(ctx context.Context, network, laddr, raddr string) (net.Conn, error) {
		return cl, dialErr
	}

	c, err := reg.getFirstConnection(context.Background(), dialFn, addrList)
	if retErr != nil {
		require.ErrorIs(t, err, retErr, i)
	} else {
		require.Nil(t, err, i)
		require.NotNil(t, c, i)
	}
}

func TestAssetsPhantomsBasics(t *testing.T) {
	phantomSet := assets.Assets().GetPhantomSubnets()
	assert.NotNil(t, phantomSet)
}

func TestAssetsPhantoms(t *testing.T) {
	log.SetOutput(io.Discard)
	dir1 := t.TempDir()

	var testPhantoms = phantoms.GetDefaultPhantomSubnets()

	_, err := assets.AssetsSetDir(dir1)
	require.ErrorIs(t, err, syscall.ENOENT) // ignore assets not found - expected

	err = assets.Assets().SetPhantomSubnets(testPhantoms)
	if err != nil {
		t.Fatal(err)
	}

	seed, err := hex.DecodeString("5a87133b68da3468988a21659a12ed2ece07345c8c1a5b08459ffdea4218d12f")
	require.Nil(t, err)

	addr4, addr6, _, err := SelectPhantom(seed, V4|V6)
	require.Nil(t, err)
	require.Equal(t, "192.122.190.178", addr4.String())
	require.Equal(t, "2001:48a8:687f:1:b292:3bab:bade:351f", addr6.String())

	addr4, addr6, _, err = SelectPhantom(seed, V6)
	require.Nil(t, err)
	require.Nil(t, addr4)
	require.Equal(t, "2001:48a8:687f:1:b292:3bab:bade:351f", addr6.String())

	addr4, addr6, _, err = SelectPhantom(seed, V4)
	require.Nil(t, err)
	require.Equal(t, "192.122.190.178", addr4.String())
	require.Nil(t, addr6)

}
