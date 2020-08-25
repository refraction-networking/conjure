package transports

import (
	"errors"
	"io"
	"net"
)

var (
	// ErrTryAgain is returned by transports when
	// it is inconclusive with the current amount of data
	// whether the transport exists in the connection.
	ErrTryAgain = errors.New("not enough information to determine transport")

	// ErrNotTransport is returned by transports when they
	// can conclusively determine that the connection does not
	// contain this transport. The caller shouldn't retry
	// with this transport.
	ErrNotTransport = errors.New("connection does not contain transport")
)

// PrefixConn allows arbitrary readers to serve as the data source
// of a net.Conn. This allows us to consume data from the socket
// while later making it available again (for things like handshakes).
type PrefixConn struct {
	net.Conn
	r io.Reader
}

func (pc PrefixConn) Read(p []byte) (int, error) {
	return pc.r.Read(p)
}

func PrependToConn(c net.Conn, r io.Reader) PrefixConn {
	return PrefixConn{Conn: c, r: io.MultiReader(r, c)}
}
