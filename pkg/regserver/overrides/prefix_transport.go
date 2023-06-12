package overrides

/*
This file is intended to be used for assigning values to the clients in bidirectional registrations
handled by the registration-server. Overwrites will only be used (and should only be provided) if
the `allow_registrar_overrides` field in the `ClientToStation` message is set to true.

*/
import (
	"bufio"
	"crypto/rand"
	"fmt"
	"io"
	"math/big"
	"os"
	"strconv"
	"strings"

	"github.com/refraction-networking/conjure/pkg/core/interfaces"
	pb "github.com/refraction-networking/gotapdance/protobuf"
)

type fieldsToOverwrite struct {
	prefix []byte
	port   int
}

type prefixIface interface {
	selectPrefix(io.Reader, *pb.ClientToStation) (*fieldsToOverwrite, bool)
}

type prefixes []prefixIface

func (pfs prefixes) selectPrefix(r io.Reader, c2s *pb.ClientToStation) (*fieldsToOverwrite, bool) {
	if len(pfs) == 0 {
		return nil, false
	} else if len(pfs) == 1 {
		return pfs[0].selectPrefix(r, c2s)
	}
	N := big.NewInt(int64(len(pfs)))
	i, err := rand.Int(r, N)
	if err != nil {
		return nil, false
	}
	if pfs[int(i.Int64())] == nil {
		return nil, false
	}
	return pfs[int(i.Int64())].selectPrefix(r, c2s)
}

type barPrefix struct {
	max, bar, id, port int
	prefix             []byte
}

func (bp barPrefix) selectPrefix(r io.Reader, c2s *pb.ClientToStation) (*fieldsToOverwrite, bool) {
	if bp.bar <= 0 {
		return nil, false
	}
	if bp.max <= 0 {
		return nil, false
	}
	if bp.bar >= bp.max {
		return &fieldsToOverwrite{bp.prefix, bp.port}, true
	}

	N := big.NewInt(int64(bp.max))
	q, err := rand.Int(r, N)
	if err != nil {
		return nil, false
	}
	B := big.NewInt(int64(bp.bar))
	if q.Cmp(B) < 0 {
		return &fieldsToOverwrite{bp.prefix, bp.port}, true
	}
	return nil, false
}

func prefixesFromFile(p string) (*prefixes, error) {
	fi, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	// close fi on exit and check for its returned error
	defer func() {
		if err := fi.Close(); err != nil {
			panic(err)
		}
	}()

	prefs, err := ParsePrefixes(fi)
	if err != nil {
		return nil, err
	}

	return prefs.prefixes, nil
}

// PrefixOverride allows the registration server to override the prefix chosen by the client when
// they register using the Prefix transport with `allow_registration_overrides` enabled.
type PrefixOverride struct {
	prefixes *prefixes
}

// ParsePrefixes allows prefix overrides to be parsed from an io.Reader
func ParsePrefixes(r io.Reader) (*PrefixOverride, error) {
	var prefixSelectors = []prefixIface{}

	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		items := strings.Fields(scanner.Text())
		if len(items) != 5 {
			// Bad line
			continue
		}

		max, err0 := strconv.ParseInt(items[0], 0, 0)
		bar, err1 := strconv.ParseInt(items[1], 0, 0)
		id, err2 := strconv.ParseInt(items[2], 0, 0)
		port, err3 := strconv.ParseInt(items[3], 0, 0)
		for i, err := range []error{err0, err1, err2, err3} {
			if err != nil {
				return nil, fmt.Errorf("prefix override parse error: (%s) %w", items[i], err)
			}
		}

		prefixSelectors = append(prefixSelectors, barPrefix{
			int(max),
			int(bar),
			int(id),
			int(port),
			[]byte(items[4]),
		})
	}
	return &PrefixOverride{(*prefixes)(&prefixSelectors)}, nil
}

// NewPrefixTransportOverride returns an object that implements the Override trait specific to when
// the Prefix transport it used. If no path is provided, then a nil Override object will be returned
// along with a nil error as this is expected behavior.
func NewPrefixTransportOverride(prefixesPath string) (interfaces.RegOverride, error) {
	if prefixesPath == "" {
		return nil, nil
	}
	p, err := prefixesFromFile(prefixesPath)
	if err != nil {
		return nil, err
	}

	return &PrefixOverride{
		prefixes: p,
	}, nil
}

// Override implements the RegOverride interface.
func (po *PrefixOverride) Override(r *pb.ClientToStation) (*pb.ClientToStation, error) {
	if r == nil {
		return r, nil
	}

	if *r.Transport != pb.TransportType_Prefix {
		return r, nil
	}

	if po.prefixes == nil {
		return r, nil
	}

	fields, ok := po.prefixes.selectPrefix(rand.Reader, r)
	if !ok || fields == nil {
		return nil, nil
	}

	if fields.port > 0 {
		// r.  set port???
	}
	params := r.GetTransportParams()
	if params == nil {
		// what to set?
	}

	return r, nil
}
