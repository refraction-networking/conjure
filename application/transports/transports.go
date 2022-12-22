package transports

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"io"
	"math/big"
	"net"

	"golang.org/x/crypto/hkdf"
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

// PrependToConn creates a PrefixConn which allows arbitrary readers to serve as
// the data source of a net.Conn.
func PrependToConn(c net.Conn, r io.Reader) PrefixConn {
	return PrefixConn{Conn: c, r: io.MultiReader(r, c)}
}

// PortSelectorRange provides a generic and basic way to return a seeded port
// selection function that uses a custom range.
func PortSelectorRange(min, max int64) func([]byte, any) (uint16, error) {
	return func(seed []byte, args any) (uint16, error) {

		// Naive Method. Get random in port range.
		hkdfReader := hkdf.New(sha256.New, seed, nil, []byte("phantom-select-port"))
		port, err := rand.Int(hkdfReader, big.NewInt(max-min))
		if err != nil {
			return 0, nil
		}

		port.Add(port, big.NewInt(min))
		return uint16(port.Uint64()), nil
	}
}
