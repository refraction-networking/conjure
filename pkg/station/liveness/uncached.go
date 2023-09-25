package liveness

import (
	"net"
	"strconv"
)

// UncachedLivenessTester implements LivenessTester interface without caching,
// PhantomIsLive will always use the network to determine phantom liveness.
type UncachedLivenessTester struct {
	*stats

	phantomIsLive func(address string) (bool, error)
}

// PhantomIsLive sends 4 TCP syn packets to determine if the host will respond
// to traffic and potentially interfere with a connection if used as a phantom
// address. Measurement results are uncached, meaning endpoints are re-scanned
// every time.
func (blt *UncachedLivenessTester) PhantomIsLive(addr string, port uint16) (bool, error) {
	if blt.phantomIsLive == nil {
		blt.phantomIsLive = phantomIsLive
	}
	live, err := blt.phantomIsLive(net.JoinHostPort(addr, strconv.Itoa(int(port))))
	if live {
		blt.stats.incPass()
	} else {
		blt.stats.incFail()
	}
	return live, err
}
