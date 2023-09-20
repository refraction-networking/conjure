package test

import (
	"github.com/refraction-networking/conjure/pkg/transports/wrapping/prefix"
	pb "github.com/refraction-networking/conjure/proto"
)

// ClientParamPermutations returns a list of client parameters for inclusions in tests that require
// variance.
func ClientParamPermutations() []any {
	paramSet := []any{}
	for _, flushPolicy := range []int32{prefix.DefaultFlush, prefix.NoAddedFlush, prefix.FlushAfterPrefix} {
		for idx := prefix.Rand; idx <= prefix.OpenSSH2; idx++ {
			for _, rand := range []bool{true, false} {
				var p int32 = int32(idx)
				params := &pb.PrefixTransportParams{
					PrefixId:          &p,
					RandomizeDstPort:  &rand,
					CustomFlushPolicy: &flushPolicy,
				}
				paramSet = append(paramSet, params)
			}
		}
	}
	return paramSet
}
