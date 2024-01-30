package dtls

import (
	"context"
	"fmt"
	"io"
	"net"
	"runtime"
	"testing"
	"time"

	"github.com/refraction-networking/conjure/pkg/dtls"
	pb "github.com/refraction-networking/conjure/proto"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
)

type mockListener struct {
	waitTime time.Duration
}

func (l *mockListener) AcceptWithContext(context.Context, *dtls.Config) (net.Conn, error) {
	time.Sleep(l.waitTime)
	return nil, fmt.Errorf("failed")
}

type mockDNAT struct{}

func (d *mockDNAT) AddEntry(clientAddr *net.IP, clientPort uint16, phantomIP *net.IP, phantomPort uint16) error {
	return nil
}

type mockReg struct {
}

func (r *mockReg) SharedSecret() []byte {
	return []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 0}
}

func (r *mockReg) GetRegistrationAddress() string {
	return "1.2.3.4"
}

func (r *mockReg) GetDstPort() uint16 {
	return 54321
}

func (r *mockReg) PhantomIP() *net.IP {
	return &net.IP{4, 3, 2, 1}
}

func (r *mockReg) TransportType() pb.TransportType {
	return pb.TransportType_DTLS
}

func (r *mockReg) TransportParams() any {
	return &pb.DTLSTransportParams{
		SrcAddr4:         &pb.Addr{IP: []byte{1, 2, 3, 4}, Port: proto.Uint32(12345)},
		RandomizeDstPort: proto.Bool(true),
	}
}

func (r *mockReg) SetTransportKeys(interface{}) error {
	return nil
}

func (r *mockReg) TransportKeys() interface{} {
	return nil
}

func (r *mockReg) TransportReader() io.Reader {
	return nil
}

func TestAcceptRespectContext(t *testing.T) {

	ctxTime := 3 * time.Second

	tr := &Transport{
		DNAT:             &mockDNAT{},
		dtlsListener:     &mockListener{ctxTime * 3},
		logDialSuccess:   func(*net.IP) {},
		logListenSuccess: func(*net.IP) {},
	}

	ctx, _ := context.WithTimeout(context.Background(), ctxTime)

	before := time.Now()
	_, err := tr.Connect(ctx, &mockReg{})

	dur := time.Since(before)

	require.NotNil(t, err)

	if dur > ctxTime*2 {
		t.Fatalf("Connect does not respect context")
	}
}

func TestGoroutineLeak(t *testing.T) {
	initialGoroutines := runtime.NumGoroutine()

	TestAcceptFail(t)

	time.Sleep(2 * time.Second)

	require.LessOrEqual(t, runtime.NumGoroutine(), initialGoroutines)
}
