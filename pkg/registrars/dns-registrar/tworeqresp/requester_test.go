package tworeqresp

import (
	"testing"

	pb "github.com/refraction-networking/conjure/proto"
	"google.golang.org/protobuf/proto"
)

type mockRequester struct {
	calls int
}

func (r *mockRequester) RequestAndRecv([]byte) ([]byte, error) {
	r.calls += 1
	return proto.Marshal(&pb.DnsPartResp{Waiting: proto.Bool(true)})
}

func (*mockRequester) Close() error { return nil }

func (*mockRequester) SetDialer(dialer dialFunc) error { return nil }

func TestSpliting(t *testing.T) {

	mtu := uint(10)

	for _, testCase := range []struct {
		name           string
		data           []byte
		chunksExpected int
	}{
		{
			name:           "< mtu",
			data:           make([]byte, mtu-1),
			chunksExpected: 1,
		},
		{
			name:           "= mtu",
			data:           make([]byte, mtu),
			chunksExpected: 1,
		},
		{
			name:           "> mtu",
			data:           make([]byte, mtu+1),
			chunksExpected: 2,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			parent := &mockRequester{}
			requester, err := NewRequester(parent, mtu)
			if err != nil {
				t.Fatalf("error creating requester: %v", err)
			}
			requester.RequestAndRecv(testCase.data)
			if parent.calls != testCase.chunksExpected {
				t.Fatalf("calls: %v, expected: %v", parent.calls, testCase.chunksExpected)
			}
		})

	}

}
