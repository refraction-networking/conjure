package connection

import (
	"net"

	"github.com/refraction-networking/conjure/pkg/station/lib"
)

// Conn is a net.Conn that contains Conjure specific connection information and callback hooks.
type Conn struct {
	net.Conn
	lib.DecoyRegistration

	closeHook func(*Conn)
}

// Close allows for a callback to track statistics on connection close.
func (c *Conn) Close() error {
	if c.closeHook != nil {
		c.closeHook(c)
	}
	if c.Conn == nil {
		return nil
	}

	return c.Conn.Close()
}
