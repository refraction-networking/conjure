package overrides

/*
This file is intended to be used for assigning values to the clients in bidirectional registrations
handled by the registration-server. Overwrites will only be used (and should only be provided) if
the `allow_registrar_overrides` field in the `ClientToStation` message is set to true.

*/
import (
	"bufio"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"strconv"
	"strings"

	"github.com/refraction-networking/conjure/pkg/core/interfaces"
	"github.com/refraction-networking/conjure/pkg/transports"
	"github.com/refraction-networking/conjure/pkg/transports/wrapping/prefix"
	pb "github.com/refraction-networking/conjure/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

type fieldsToOverwrite struct {
	prefix           []byte
	port             int
	id               int
	flushAfterPrefix bool
}

type prefixIface interface {
	// Includes C2SWrapper just in case we ever want to do geoip things with the client address.
	// Also this allows us to write / overwrite the transport params that the station will see.
	selectPrefix(io.Reader, *pb.C2SWrapper) (*fieldsToOverwrite, bool)
}

type prefixes []prefixIface

func (pfs prefixes) selectPrefix(r io.Reader, c2s *pb.C2SWrapper) (*fieldsToOverwrite, bool) {
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
	flushAfterPrefix   bool
}

func (bp barPrefix) selectPrefix(r io.Reader, c2s *pb.C2SWrapper) (*fieldsToOverwrite, bool) {
	if bp.bar <= 0 {
		return nil, false
	}
	if bp.max <= 0 {
		return nil, false
	}
	if bp.bar >= bp.max {
		return &fieldsToOverwrite{bp.prefix, bp.port, bp.id, bp.flushAfterPrefix}, true
	}

	N := big.NewInt(int64(bp.max))
	q, err := rand.Int(r, N)
	if err != nil {
		return nil, false
	}
	B := big.NewInt(int64(bp.bar))
	if q.Cmp(B) < 0 {
		return &fieldsToOverwrite{bp.prefix, bp.port, bp.id, bp.flushAfterPrefix}, true
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
func ParsePrefixes(conf io.Reader) (*PrefixOverride, error) {
	var prefixSelectors = []prefixIface{}

	scanner := bufio.NewScanner(conf)
	for scanner.Scan() {
		line := scanner.Text()
		if len(line) == 0 {
			continue
		} else if line[0] == '#' {
			continue
		}
		items := strings.Fields(line)
		if len(items) != 5 {
			return nil, fmt.Errorf("malformed line: %s", line)
		}

		max, err0 := strconv.ParseInt(items[0], 0, 0)
		bar, err1 := strconv.ParseInt(items[1], 0, 0)
		if max == 0 && bar == 0 {
			continue
		}
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
			false, // TODO - make this not static
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
func (po *PrefixOverride) Override(reg *pb.C2SWrapper, randReader io.Reader) error {
	if reg == nil || reg.GetRegistrationPayload() == nil {
		return ErrMissingRegistration
	} else if reg.GetRegistrationPayload().GetTransport() != pb.TransportType_Prefix {
		return nil
	} else if po.prefixes == nil {
		return nil
	}

	fields, ok := po.prefixes.selectPrefix(randReader, reg)
	if !ok || fields == nil {
		return nil
	}

	// if we have made it this far we overwrite the prefix even if the new one is empty
	params := &pb.PrefixTransportParams{}
	err := transports.UnmarshalAnypbTo(reg.GetRegistrationPayload().GetTransportParams(), params)
	if err != nil {
		return err
	}
	params.Prefix = fields.prefix
	var i int32 = int32(fields.id)
	params.PrefixId = &i
	params.FlushAfterPrefix = &fields.flushAfterPrefix

	if reg.GetRegistrationResponse() == nil {
		reg.RegistrationResponse = &pb.RegistrationResponse{}
	}

	if fields.port > 0 {
		p := uint32(fields.port)
		reg.RegistrationResponse.DstPort = &p
	}

	anypbParams, err := anypb.New(params)
	if err != nil {
		return err
	}

	reg.RegistrationResponse.TransportParams = anypbParams

	return nil
}

var (
	ErrNotPrefixTransport  = errors.New("registration does not use Prefix transport")
	ErrMissingRegistration = errors.New("no registration to modify")
)

// RandPrefixOverride allows the registration server to override the prefix chosen by the client when
// they register using the Prefix transport with `disable_registration_overrides` enabled.
type RandPrefixOverride struct{}

// NewRandPrefixOverride returns an object that implements the Override trait specific to
// when the Prefix transport it used. This is primarily for testing to ensure that the override
// system works in practice.
func NewRandPrefixOverride() *RandPrefixOverride {
	return &RandPrefixOverride{}
}

// Override implements the RegOverride interface.
func (rpo *RandPrefixOverride) Override(reg *pb.C2SWrapper, randReader io.Reader) error {
	if reg == nil || reg.GetRegistrationPayload() == nil {
		return ErrMissingRegistration
	} else if reg.GetRegistrationPayload().GetTransport() != pb.TransportType_Prefix {
		return nil
	}

	newPrefix, err := prefix.TryFromID(prefix.Rand)
	if err != nil {
		return err
	}

	// if we have made it this far we overwrite the prefix even if the new one is empty
	params := &pb.PrefixTransportParams{}
	err = transports.UnmarshalAnypbTo(reg.GetRegistrationPayload().GetTransportParams(), params)
	if err != nil {
		return err
	}

	var fp = newPrefix.FlushAfterPrefix()
	var i int32 = int32(newPrefix.ID())
	params.PrefixId = &i
	params.FlushAfterPrefix = &fp
	params.Prefix = newPrefix.Bytes()

	if reg.GetRegistrationResponse() == nil {
		reg.RegistrationResponse = &pb.RegistrationResponse{}
	}

	port := newPrefix.DstPort(reg.GetSharedSecret())
	if port > 0 {
		p := uint32(port)
		reg.RegistrationResponse.DstPort = &p
	}

	anypbParams, err := anypb.New(params)
	if err != nil {
		return err
	}

	reg.RegistrationResponse.TransportParams = anypbParams

	return nil
}

// FixedPrefixOverride allows the registration server to override the prefix chosen by the client when
// they register using the Prefix transport with `disable_registration_overrides` enabled.
type FixedPrefixOverride struct {
	p prefix.Prefix
}

// NewFixedPrefixOverride returns an object that implements the Override trait specific to
// when the Prefix transport it used. This is primarily for testing to ensure that the override
// system works in practice.
func NewFixedPrefixOverride(p prefix.Prefix) *FixedPrefixOverride {
	return &FixedPrefixOverride{
		p,
	}
}

// Override implements the RegOverride interface.
func (fpo *FixedPrefixOverride) Override(reg *pb.C2SWrapper, randReader io.Reader) error {
	if reg == nil || reg.GetRegistrationPayload() == nil {
		return ErrMissingRegistration
	} else if reg.GetRegistrationPayload().GetTransport() != pb.TransportType_Prefix {
		return nil
	}

	// if we have made it this far we overwrite the prefix even if the new one is empty
	params := &pb.PrefixTransportParams{}
	err := transports.UnmarshalAnypbTo(reg.GetRegistrationPayload().GetTransportParams(), params)
	if err != nil {
		return err
	}

	var fp = fpo.p.FlushAfterPrefix()
	var i int32 = int32(fpo.p.ID())
	params.PrefixId = &i
	params.FlushAfterPrefix = &fp
	params.Prefix = fpo.p.Bytes()

	if reg.GetRegistrationResponse() == nil {
		reg.RegistrationResponse = &pb.RegistrationResponse{}
	}

	port := fpo.p.DstPort(reg.GetSharedSecret())
	if port > 0 {
		p := uint32(port)
		reg.RegistrationResponse.DstPort = &p
	}

	anypbParams, err := anypb.New(params)
	if err != nil {
		return err
	}

	reg.RegistrationResponse.TransportParams = anypbParams

	return nil
}
