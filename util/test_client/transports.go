package main

import (
	"github.com/refraction-networking/conjure/pkg/core/interfaces"
	"github.com/refraction-networking/conjure/pkg/transports/client"
	pb "github.com/refraction-networking/conjure/proto"
)

type transport struct {
	interfaces.Transport
	generationFilter func(uint32) bool
}

func minTransportPermutations() []transport {
	t := []transport{}

	for _, r := range []bool{true, false} {
		m1, err := transports.NewWithParams("min", &pb.GenericTransportParams{RandomizeDstPort: &r})
		if err != nil {
			logger().Error("Failed to create min transport", "err", err)
			return nil
		}
		t = append(t, transport{m1, defaultGenFilter})
	}
	logger().Debug("MinTransportPermutations", "len", len(t))
	return t
}

func prefixTransportPermutations() []transport {
	return []transport{}
}

func obfs4TransportPermutations() []transport {
	return []transport{}
}

func dtlsTransportPermutations() []transport {
	return []transport{}
}
