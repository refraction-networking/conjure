package main

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"net"

	"github.com/pion/dtls/v2/examples/util"
	"github.com/refraction-networking/conjure/pkg/station/oscur0"
)

func main() {
	var remoteAddr = flag.String("saddr", "127.0.0.1:6666", "remote address")
	// var localAddr = flag.String("laddr", "", "source address")
	var pubkey = flag.String("secret", "0b63baad7f2f4bb5b547c53adc0fbb179852910607935e6f4b5639fd989b1156", "shared secret")
	var covert = flag.String("covert", "1.2.3.4:5678", "covert address")
	flag.Parse()
	// Prepare the IP to connect to
	// laddr, err := net.ResolveUDPAddr("udp", *localAddr)
	// util.Check(err)

	addr, err := net.ResolveUDPAddr("udp", *remoteAddr)
	util.Check(err)

	pubkeyBytes, err := hex.DecodeString(*pubkey)
	util.Check(err)
	pubkey32Bytes := [32]byte{}
	copy(pubkey32Bytes[:], pubkeyBytes)

	pConn, err := net.ListenUDP("udp", nil)
	util.Check(err)

	conn, err := oscur0.ClientWithContext(context.Background(), pConn, addr, oscur0.Config{Phantom: *covert, PubKey: pubkey32Bytes})
	util.Check(err)

	fmt.Println("Connected; type 'exit' to shutdown gracefully")

	// Simulate a chat session
	util.Chat(conn)

}
