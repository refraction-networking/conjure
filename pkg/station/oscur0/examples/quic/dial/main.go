package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"net"

	"github.com/pion/dtls/v2/examples/util"
	"github.com/quic-go/quic-go"
)

func main() {
	var remoteAddr = flag.String("raddr", "127.0.0.1:6666", "remote address")
	// var pubkey = flag.String("secret", "0b63baad7f2f4bb5b547c53adc0fbb179852910607935e6f4b5639fd989b1156", "shared secret")
	// var covert = flag.String("covert", "1.2.3.4:5678", "covert address")
	flag.Parse()

	addr, err := net.ResolveUDPAddr("udp", *remoteAddr)
	util.Check(err)

	// pubkeyBytes, err := hex.DecodeString(*pubkey)
	// util.Check(err)

	pconn, err := net.ListenUDP("udp", nil)
	util.Check(err)
	tp := quic.Transport{
		Conn: pconn,
	}

	econn, err := tp.DialEarly(context.Background(), addr, &tls.Config{InsecureSkipVerify: true}, &quic.Config{})
	util.Check(err)

	stream, err := econn.OpenStream()
	util.Check(err)

	fmt.Println("Connected; type 'exit' to shutdown gracefully")

	// Simulate a chat session
	util.Chat(stream)

}
