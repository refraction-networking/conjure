// Package queuepacketconn is facilities for embedding packet-based reliability
// protocols inside other protocols.
//
// https://github.com/net4people/bbs/issues/9
package queuepacketconn

import "errors"

// QueueSize is the size of send and receive queues in QueuePacketConn and
// RemoteMap.
const QueueSize = 128

var errClosedPacketConn = errors.New("operation on closed connection")
var errNotImplemented = errors.New("not implemented")

// DummyAddr is a placeholder net.Addr, for when a programming interface
// requires a net.Addr but there is none relevant. All DummyAddrs compare equal
// to each other.
type DummyAddr struct{}

func (addr DummyAddr) Network() string { return "dummy" }
func (addr DummyAddr) String() string  { return "dummy" }
