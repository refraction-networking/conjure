package dtls

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

var maxMsgSize = 65535
var conf = &heartbeatConfig{Interval: 1 * time.Second, Heartbeat: []byte("hihihihihihihihihi")}

type mockStream struct {
	net.Conn
}

func (*mockStream) BufferedAmount() uint64                  { return 0 }
func (*mockStream) SetBufferedAmountLowThreshold(th uint64) {}
func (*mockStream) OnBufferedAmountLow(f func())            {}

func mockStreams() (msgStream, msgStream) {
	server, client := net.Pipe()
	return &mockStream{server}, &mockStream{client}
}

func TestHeartbeatReadWrite(t *testing.T) {
	server, client := mockStreams()

	s, err := heartbeatServer(server, conf, maxMsgSize)
	require.Nil(t, err)

	err = heartbeatClient(client, conf)
	require.Nil(t, err)

	sent := uint32(0)
	recvd := uint32(0)
	toSend := []byte("testtt")
	sleepInterval := 100 * time.Millisecond
	var wg sync.WaitGroup

	ctx, cancel := context.WithTimeout(
		context.Background(),
		time.Duration(10*sleepInterval+sleepInterval/2))

	defer cancel()

	wg.Add(1)
	go func(ctx1 context.Context) {
		defer wg.Done()
		for {
			select {
			case <-ctx1.Done():
				server.Close()
				return
			default:
				buffer := make([]byte, 4096)
				n, err := s.Read(buffer)
				if err != nil {
					return
				}
				if string(toSend) != string(buffer[:n]) {
					t.Log("read incorrect value", toSend, buffer[:n])
					t.Fail()
					return
				}
				atomic.AddUint32(&recvd, 1)
			}
		}
	}(ctx)

	wg.Add(1)
	go func(ctx2 context.Context) {
		defer wg.Done()
		for {
			select {
			case <-ctx2.Done():
				client.Close()
				return
			default:
				_, err := client.Write(toSend)
				if err != nil {
					if !errors.Is(err, net.ErrClosed) {
						t.Log("encountered error writing", err)
						t.Fail()
					}
					return
				}
				atomic.AddUint32(&sent, 1)
			}
			time.Sleep(sleepInterval)
		}
	}(ctx)

	wg.Wait()
	require.Equal(t, atomic.LoadUint32(&sent), atomic.LoadUint32(&recvd))
}

func TestHeartbeatSend(t *testing.T) {
	server, client := mockStreams()

	readCh := make(chan []byte)

	go func() {
		for {
			buffer := make([]byte, 4096)
			n, err := server.Read(buffer)
			if err != nil {
				continue
			}

			readCh <- buffer[:n]
		}
	}()

	err := heartbeatClient(client, conf)
	require.Nil(t, err)

	duration := 2

	ctx, cancel := context.WithTimeout(
		context.Background(),
		2*conf.Interval+10*time.Millisecond)
	defer cancel()

	hbCount := 0
	for {
		select {
		case b := <-readCh:
			require.Equal(t, conf.Heartbeat, b)
			hbCount++
		case <-ctx.Done():
			require.Equal(t, duration*2+1, hbCount)
			return
		}
	}

}

func TestHeartbeatTimeout(t *testing.T) {
	server, client := mockStreams()
	go func() {
		for {
			buffer := make([]byte, 4096)
			_, err := client.Read(buffer)
			if err != nil {
				return
			}
		}
	}()

	s, err := heartbeatServer(server, conf, maxMsgSize)
	require.Nil(t, err)

	_, err = s.Write([]byte("123"))
	require.Nil(t, err)

	stop := time.After(conf.Interval + 10*time.Millisecond)
	<-stop
	_, err = s.Write([]byte("123"))
	require.NotNil(t, err)

}

func TestHeartbeatInsufficientBuf(t *testing.T) {
	server, client := mockStreams()

	s, err := heartbeatServer(server, conf, maxMsgSize)
	require.Nil(t, err)

	err = heartbeatClient(client, conf)
	require.Nil(t, err)

	toSend := []byte("testtt")
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		buffer := make([]byte, 1)
		_, err := s.Read(buffer)
		require.ErrorIs(t, err, ErrInsufficientBuffer)
	}()

	_, err = client.Write(toSend)
	require.Nil(t, err)

	wg.Wait()
}
