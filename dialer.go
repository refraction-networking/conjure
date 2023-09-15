package conjure

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"

	"github.com/refraction-networking/conjure/pkg/client"
	"github.com/refraction-networking/conjure/pkg/core/interfaces"
	pb "github.com/refraction-networking/conjure/proto"
)

// IPSupport is a bitmask of supported IP versions.
type IPSupport client.IPSupport

const (
	// V4 indicates that client support for IPv4 is enabled.
	V4 IPSupport = 1 << iota
	// V6 indicates that client support for IPv6 is enabled.
	V6
)

// Dialer contains options and implements advanced functions for establishing TapDance connection.
type Dialer struct {
	// If not specified, the default system dialer will be used. Will be ignored if DialWithLaddr
	// is specified.
	//
	// THIS IS REQUIRED TO INTERFACE WITH ANDROID PROXY APPLICATIONS
	//      we use their dialer to prevent connection loopback into our own proxy
	//      connection when tunneling the whole device.
	//
	// Deprecated: Dialer does not allow specifying the local address used for NAT traversal in some
	// transports. Use DialWithLaddr instead.
	Dialer func(context.Context, string, string) (net.Conn, error)

	// DialWithLaddr allows a custom dialer to be used for the underlying TCP/UDP connection.
	// If not specified, the default system dialer will be used. If both this and the Dialer option
	// are specified, DialWithLaddr will be used.
	//
	// THIS IS REQUIRED TO INTERFACE WITH ANDROID PROXY APPLICATIONS
	//		we use their dialer to prevent connection loopback into our own proxy
	//		connection when tunneling the whole device.
	DialWithLaddr interfaces.DialFunc

	// The type of registrar to use when performing Conjure registrations.
	Registrar interfaces.Registrar

	// DisableRegistrarOverrides Indicates whether the client will allow the registrar to provide
	// alternative parameters that may work better in substitute for the deterministically selected
	// parameters. This only works for bidirectional registration methods where the client receives
	// a RegistrationResponse.
	DisableRegistrarOverrides bool

	// The type of transport to use for Conjure connections.
	Transport interfaces.Transport

	// // RegDelay is the delay duration to wait for registration ingest.
	// RegDelay time.Duration

	UseProxyHeader bool
	IPv            IPSupport

	// Subnet that we want to limit to (or empty if they're all fine) this is used for debug only.
	PhantomNet string

	// Assets provide stations configuration including available Phantom Subnets and decoy hosts
	// to be used with the decoy-registrar. If neither the Assets nor the AssetsPath is specified,
	// the default assets path will be used. If no assets are found an error is returned.
	Assets     *pb.ClientConf
	AssetsPath string
}

// Dial connects to the address on the named network.
//
// The only supported network at this time: "tcp".
// The address has the form "host:port".
// The host must be a literal IP address, or a host name that can be
// resolved to IP addresses.
// To avoid abuse, only certain whitelisted ports are allowed.
//
// Example: Dial("tcp", "golang.org:80")
func Dial(network, address string) (net.Conn, error) {
	var d Dialer
	return d.Dial(network, address)
}

// Dial connects to the address on the named network.
func (d *Dialer) Dial(network, address string) (net.Conn, error) {
	return d.DialContext(context.Background(), network, address)
}

// DialContext connects to the address on the named network using the provided context.
// Long deadline is advised, since conjure may try multiple registration strategies.
//
// The only supported network at this time: "tcp".
// The address has the form "host:port".
// The host must be a literal IP address, or a host name that can be
// resolved to IP addresses.
// To avoid abuse, only certain whitelisted ports are allowed.
//
// Example: Dial("tcp", "golang.org:80")
func (d *Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if network != "tcp" {
		return nil, &net.OpError{Op: "dial", Net: network, Err: net.UnknownNetworkError(network)}
	}
	if len(address) > 0 {
		_, _, err := net.SplitHostPort(address)
		if err != nil {
			return nil, err
		}
	}

	if d.DialWithLaddr != nil && d.Dialer != nil {
		return nil, fmt.Errorf("both DialWithLaddr and Dialer are defined, only define DialWithLaddr")
	}

	if d.Dialer != nil {
		d.DialWithLaddr = func(ctx context.Context, network, laddr, raddr string) (net.Conn, error) {
			if laddr != "" {
				return nil, errUnsupportedLaddr
			}
			return d.Dialer(ctx, network, raddr)
		}
	}

	if d.DialWithLaddr == nil {
		// custom dialer is not set, use default
		defaultDialer := net.Dialer{}
		dialMutex := sync.Mutex{}
		d.DialWithLaddr = func(ctx context.Context, network, laddr, raddr string) (net.Conn, error) {
			localAddr, err := resolveAddr(network, laddr)
			if err != nil {
				return nil, fmt.Errorf("error resolving laddr: %v", err)
			}

			dialMutex.Lock()
			defer dialMutex.Unlock()

			defaultDialer.LocalAddr = localAddr

			return defaultDialer.DialContext(ctx, network, raddr)
		}
	}

	// Conjure
	var cjSession *client.ConjureSession

	if d.Transport == nil {
		return nil, errors.New("missing transport")
	}

	// If specified, only select a phantom from a given range
	if d.PhantomNet != "" {
		_, phantomRange, err := net.ParseCIDR(d.PhantomNet)
		if err != nil {
			return nil, errors.New("Invalid Phantom network goal")
		}
		cjSession = client.FindConjureSessionInRange(address, d.Transport, phantomRange)
		if cjSession == nil {
			return nil, errors.New("Failed to find Phantom in target subnet")
		}
	} else {
		cjSession = client.MakeConjureSession(address, d.Transport)
	}

	cjSession.Dialer = d.DialWithLaddr
	cjSession.UseProxyHeader = d.UseProxyHeader
	cjSession.DisableRegistrarOverrides = d.DisableRegistrarOverrides
	cjSession.V6Support = client.IPSupport(d.IPv)

	if len(address) == 0 {
		return nil, errors.New("Conjure requires a target address to be set")
	}
	return client.DialConjure(ctx, cjSession, d.Registrar)
}

// DialProxy establishes direct connection to TapDance station proxy.
// Users are expected to send HTTP CONNECT request next.
func (d *Dialer) DialProxy() (net.Conn, error) {
	return d.DialProxyContext(context.Background())
}

// DialProxyContext establishes direct connection to TapDance station proxy using the provided context.
// Users are expected to send HTTP CONNECT request next.
func (d *Dialer) DialProxyContext(ctx context.Context) (net.Conn, error) {
	return d.DialContext(ctx, "tcp", "")
}

func resolveAddr(network, addrStr string) (net.Addr, error) {
	if addrStr == "" {
		return nil, nil
	}

	if strings.Contains(network, "tcp") {
		return net.ResolveTCPAddr(network, addrStr)
	}

	return net.ResolveUDPAddr(network, addrStr)
}

var errUnsupportedLaddr = fmt.Errorf("dialer does not support laddr")
