package main

import (
	"errors"

	"github.com/refraction-networking/conjure/pkg/registrars/registration"
	pb "github.com/refraction-networking/conjure/proto"
	"github.com/refraction-networking/gotapdance/tapdance"
)

type registrar struct {
	tapdance.Registrar
	generationFilter func(uint32) bool
}

func decoyRegistrarPermutations() []registrar {
	return []registrar{}
}

func apiRegistrarPermutations() []registrar {
	ts := []registrar{}
	for _, r := range []bool{true, false} {
		var apiEndpoint string = defaultAPIEndpoint
		if r {
			apiEndpoint = defaultBDAPIEndpoint
		}

		m1, err := registration.NewAPIRegistrar(&registration.Config{
			Target:             apiEndpoint,
			Bidirectional:      r,
			MaxRetries:         3,
			SecondaryRegistrar: nil,
		})
		if err != nil {
			return nil
		}
		ts = append(ts, registrar{m1, defaultGenFilter})
	}

	return ts
}

func dnsRegistrarPermutations() []registrar {
	return []registrar{}
}

// NewDNSRegistrarFromConf creates a DNSRegistrar from DnsRegConf protobuf. Uses the pubkey in conf as default. If it is not supplied (nil), uses fallbackKey instead.
func newDNSRegistrarFromConf(conf *pb.DnsRegConf, bidirectional bool, maxTries int, fallbackKey []byte) (*registration.DNSRegistrar, error) {
	pubkey := conf.Pubkey
	if pubkey == nil {
		pubkey = fallbackKey
	}
	var method registration.DNSTransportMethodType
	switch *conf.DnsRegMethod {
	case pb.DnsRegMethod_UDP:
		method = registration.UDP
	case pb.DnsRegMethod_DOT:
		method = registration.DoT
	case pb.DnsRegMethod_DOH:
		method = registration.DoH
	default:
		return nil, errors.New("unknown reg method in conf")
	}

	return registration.NewDNSRegistrar(&registration.Config{
		DNSTransportMethod: method,
		Target:             *conf.Target,
		BaseDomain:         *conf.Domain,
		Pubkey:             pubkey,
		UTLSDistribution:   *conf.UtlsDistribution,
		MaxRetries:         maxTries,
		Bidirectional:      bidirectional,
		STUNAddr:           *conf.StunServer,
	})
}
