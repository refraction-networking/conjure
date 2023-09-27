package main

import (
	"context"
	"flag"
	"fmt"
	"net"

	"github.com/pion/dtls/v2/examples/util"
	"github.com/refraction-networking/conjure/pkg/dtls"
)

func main() {
	var remoteAddr = flag.String("saddr", "127.0.0.1:6666", "remote address")
	var localAddr = flag.String("laddr", "", "source address")
	var secret = flag.String("secret", "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef", "shared secret")
	flag.Parse()
	// Prepare the IP to connect to
	laddr, err := net.ResolveUDPAddr("udp", *localAddr)
	util.Check(err)

	addr, err := net.ResolveUDPAddr("udp", *remoteAddr)
	util.Check(err)

	sharedSecret := []byte(*secret)

	udpConn, err := net.DialUDP("udp", laddr, addr)
	util.Check(err)

	dtlsConn, err := dtls.ClientWithContext(context.Background(), udpConn, &dtls.Config{PSK: sharedSecret, SCTP: dtls.ClientOpen})
	util.Check(err)

	fmt.Println("Connected; type 'exit' to shutdown gracefully")

	// Simulate a chat session
	util.Chat(dtlsConn)

}
