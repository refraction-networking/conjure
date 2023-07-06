package dtls

import (
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

var conf = &heartbeatConfig{Interval: 1 * time.Second, Heartbeat: []byte("hihihihihihihihihi")}

func TestHeartbeatReadWrite(t *testing.T) {
	server, client := net.Pipe()

	s, err := heartbeatServer(server, conf)
	require.Nil(t, err)

	err = heartbeatClient(client, conf)
	require.Nil(t, err)

	sent := uint32(0)
	recvd := uint32(0)
	toSend := []byte("testtt")
	stop := time.After(conf.Interval * 2)

	go func() {
		for {
			select {
			case <-stop:
				return
			default:
				buffer := make([]byte, 4096)
				n, err := s.Read(buffer)
				if err != nil {
					continue
				}
				require.Equal(t, toSend, buffer[:n])
				atomic.AddUint32(&recvd, 1)
			}
		}
	}()

	go func() {
		for {
			select {
			case <-stop:
				return
			default:
				_, err := client.Write(toSend)
				require.Nil(t, err)
				atomic.AddUint32(&sent, 1)
				time.Sleep(10 * time.Millisecond)
			}
		}
	}()

	<-stop

	require.Equal(t, atomic.LoadUint32(&sent), atomic.LoadUint32(&recvd))
}

func TestHeartbeatSend(t *testing.T) {
	server, client := net.Pipe()

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
	stop := time.After(conf.Interval*time.Duration(duration) + 10*time.Millisecond)

	hbCount := 0
	for {
		select {
		case b := <-readCh:
			require.Equal(t, conf.Heartbeat, b)
			hbCount++
		case <-stop:
			require.Equal(t, duration*2+1, hbCount)
			return
		}
	}

}

func TestHeartbeatTimeout(t *testing.T) {
	server, client := net.Pipe()
	go func() {
		for {
			buffer := make([]byte, 4096)
			_, err := client.Read(buffer)
			if err != nil {
				return
			}
		}
	}()

	s, err := heartbeatServer(server, conf)
	require.Nil(t, err)

	_, err = s.Write([]byte("123"))
	require.Nil(t, err)

	stop := time.After(conf.Interval + 10*time.Millisecond)
	<-stop
	_, err = s.Write([]byte("123"))
	require.NotNil(t, err)

}
