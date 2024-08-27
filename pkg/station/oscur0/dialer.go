package oscur0

// import (
// 	"context"
// 	"fmt"
// 	"net"
// )

// func NewDialer(conf *Config) (*Dialer, error) {
// 	inner := conf.innerDialer

// 	if inner == nil {
// 		inner = func(ctx context.Context, network, laddr, raddr string) (net.Conn, error) {
// 			defaultDialer := net.Dialer{}
// 			localAddr, err := resolveAddr(network, laddr)
// 			if err != nil {
// 				return nil, fmt.Errorf("error resolving laddr: %v", err)
// 			}

// 			defaultDialer.LocalAddr = localAddr
// 			return defaultDialer.DialContext(ctx, network, raddr)
// 		}
// 	}

// 	return &Dialer{inner: inner, pubkey: pubkey32Bytes}, nil
// }

// func (d *Dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {

// 	pconn, err := net.ListenUDP("udp", nil)
// 	if err != nil {
// 		return nil, fmt.Errorf("error listening udp pconn: %v", err)
// 	}

// 	return ServerWithContext(ctx, pconn)

// }
