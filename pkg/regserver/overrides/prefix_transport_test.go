package overrides

import (
	"bytes"
	"encoding/hex"
	"io"
	"io/fs"
	"os"
	"strings"
	"syscall"
	"testing"

	pb "github.com/refraction-networking/gotapdance/protobuf"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/anypb"
)

func TestOverrideNewPrefix(t *testing.T) {
	// no path provided
	np, err := NewPrefixTransportOverride("")
	require.Nil(t, err)
	require.Nil(t, np)

	tmpdir := t.TempDir()
	path := tmpdir + "/prefix_tspt.dat"

	// path provided, but file not exist
	np, err = NewPrefixTransportOverride(path)
	require.Nil(t, np)
	e, ok := err.(*fs.PathError)
	if ok && e.Err != syscall.ENOENT {
		t.Fatalf("errno: %d, expected: %d", e.Err, syscall.ENOENT)
	}

	f, err := os.Create(path)
	require.Nil(t, err)

	// file exists, but is empty
	np, err = NewPrefixTransportOverride(path)
	require.Equal(t, np, &PrefixOverride{(*prefixes)(&[]prefixIface{})})
	require.Nil(t, err)

	// file exists, but incorrect format
	_, err = f.Write([]byte("100"))
	require.Nil(t, err)
	np, err = NewPrefixTransportOverride(path)
	require.Nil(t, np)
	require.ErrorContains(t, err, "malformed line:")

	err = os.Truncate(path, 0)
	require.Nil(t, err)
	_, err = f.Seek(0, 0)
	require.Nil(t, err)

	// file exists and is properly formatted.
	_, err = f.Write([]byte("100 10 0x21 80 HTT\n1000 10 0x22 22 SSH"))
	require.Nil(t, err)
	np, err = NewPrefixTransportOverride(path)
	require.Nil(t, err)
	require.Equal(t, 2, len(([]prefixIface)(*(np.(*PrefixOverride).prefixes))))
}

func TestOverrideSelectPrefix(t *testing.T) {

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
		{"two prefixes first ignored", "0 0 0x21 80 HTT\n1000 10 0x22 22 SSH", "SSH", true, 22, rr},
		{"two prefixes select first", "1000 10 0x21 80 HTT\n1000 10 0x22 22 SSH", "HTT", true, 80, rr},
		{"two prefixes select second", "1000 10 0x21 80 HTT\n1000 10 0x22 22 SSH", "SSH", true, 22, bytes.NewReader(d("01000000"))},
		{"comment line and single prefix", "#this is a comment\n1000 10 0x22 22 SSH", "SSH", true, 22, rr},
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
		_, err := rr.Seek(0, io.SeekStart)
		require.Nil(t, err)
	}
}

type expected struct {
	wantErr   bool
	wantedErr error
	port      uint32
	prefix    []byte
}

func TestPrefixOverride_Override(t *testing.T) {
	var po = &PrefixOverride{}
	var c *pb.C2SWrapper
	var out expected
	var i = 0
	test := func(t *testing.T) {
		i += 1
		rr := bytes.NewReader(d("00000000"))
		err := po.Override(c, rr)

		if out.wantErr {
			require.ErrorIs(t, err, out.wantedErr, "t.Run %d", i)
			return
		}
		require.Nil(t, err)
		require.NotNil(t, c.RegistrationResponse)
		require.Equal(t, uint32(out.port), c.RegistrationResponse.GetDstPort())
		// require.Equal(t, out.prefix, c.)
	}

	out = expected{true, ErrMissingRegistration, 0, nil}
	t.Run("select using uninitialized PrefixOverride", test)

	c = &pb.C2SWrapper{}
	T := true
	params := &pb.GenericTransportParams{}
	p, err := anypb.New(params)
	require.Nil(t, err)

	ttMin := pb.TransportType_Min
	reg := &pb.ClientToStation{
		AllowRegistrarOverrides: &T,
		TransportParams:         p,
		Transport:               &ttMin,
	}
	c.RegistrationPayload = reg

	out = expected{true, ErrNotPrefixTransport, 0, []byte{}}
	t.Run("registration wrong tt and params", test)

	ttPrefix := pb.TransportType_Prefix
	paramsPref, _ := anypb.New(&pb.PrefixTransportParams{})
	c.RegistrationPayload.Transport = &ttPrefix
	c.RegistrationPayload.TransportParams = paramsPref

	out = expected{true, nil, 0, []byte{}}
	t.Run("empty prefix override set", test)

	conf := strings.NewReader("100 1 0x22 22 SSH")
	po, err = ParsePrefixes(conf)
	require.Nil(t, err)

	out = expected{false, nil, 22, []byte("SSH")}
	t.Run("select from single prefix", test)

	conf = strings.NewReader("100 1 0x22 -1 ABC")
	po, err = ParsePrefixes(conf)
	require.Nil(t, err)
	tmpPort := uint32(1024)
	c.RegistrationResponse.DstPort = &tmpPort

	out = expected{false, nil, 1024, []byte("ABC")}
	t.Run("select prefix with port override disabled", test)
}

func d(s string) []byte {
	x, e := hex.DecodeString(s)
	if e != nil {
		panic(e)
	}
	return x
}

// 	type out struct {
// 		id int32
// 		port
// 	}
// 	type fields struct {
// 		prefixes *prefixes
// 	}
// 	type args struct {
// 		reg  *pb.ClientToStation
// 		resp *pb.RegistrationResponse
// 	}
// 	tests := []struct {
// 		name    string
// 		fields  fields
// 		args    args
// 		want	out
// 		wantErr bool
// 		wantedErr    error
// 	}{
// 		// TODO: Add test cases.
// 	}
// 	for _, tt := range tests {
// 		t.Run(tt.name, func(t *testing.T) {
// 			po := &PrefixOverride{
// 				prefixes: tt.fields.prefixes,
// 			}
// 			err := po.Override(tt.args.reg, tt.args.resp)
// 			if (err != nil) != tt.wantErr {
// 				t.Errorf("PrefixOverride.Override() error = %v, wantErr %v", err, tt.wantErr)
// 				return
// 			}
// 			if !reflect.DeepEqual( tt.want) {
// 				t.Errorf("PrefixOverride.Override() = %v, want %v", got, tt.want)
// 			}
// 		})
// 	}
// }
