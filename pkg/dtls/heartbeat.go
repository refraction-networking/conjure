package dtls

import (
	"bytes"
	"errors"
	"sync/atomic"
	"time"
)

var ErrInsufficientBuffer = errors.New("buffer too small to hold the received data")

type hbConn struct {
	msgStream

	recvCh  chan errBytes
	waiting uint32
	hb      []byte
	timeout time.Duration
	buffer  []byte
}

type errBytes struct {
	b   []byte
	err error
}

// heartbeatServer listens for heartbeat over conn with config
func heartbeatServer(stream msgStream, config *heartbeatConfig, maxMessageSize int) (*hbConn, error) {
	conf := validate(config)

	c := &hbConn{msgStream: stream,
		recvCh:  make(chan errBytes),
		timeout: conf.Interval,
		hb:      conf.Heartbeat,
		buffer:  make([]byte, maxMessageSize),
	}

	atomic.StoreUint32(&c.waiting, 2)

	go c.recvLoop()
	go c.hbLoop()

	return c, nil
}

func (c *hbConn) hbLoop() {
	for {
		if atomic.LoadUint32(&c.waiting) == 0 {
			// c.Close()
			return
		}

		atomic.StoreUint32(&c.waiting, 0)
		time.Sleep(c.timeout)
	}

}

func (c *hbConn) recvLoop() {
	for {

		n, err := c.Read(c.buffer)

		if bytes.Equal(c.hb, c.buffer[:n]) {
			atomic.AddUint32(&c.waiting, 1)
			continue
		}

		c.recvCh <- errBytes{c.buffer[:n], err}
	}

}

func (c *hbConn) Read(b []byte) (int, error) {
	readBytes := <-c.recvCh
	if readBytes.err != nil {
		return 0, readBytes.err
	}

	if len(b) < len(readBytes.b) {
		return 0, ErrInsufficientBuffer
	}

	n := copy(b, readBytes.b)

	return n, nil
}

// heartbeatClient sends heartbeats over conn with config
func heartbeatClient(conn msgStream, config *heartbeatConfig) error {
	conf := validate(config)
	go func() {
		for {
			_, err := conn.Write(conf.Heartbeat)
			if err != nil {
				return
			}

			time.Sleep(conf.Interval / 2)
		}

	}()
	return nil
}
