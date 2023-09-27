package main

import (
	"flag"
	"fmt"
	"net"

	"github.com/pion/dtls/v2/examples/util"
	"github.com/refraction-networking/conjure/pkg/dtls"
)

func main() {
	var localAddr = flag.String("laddr", "[::]:6666", "source address")
	var secret = flag.String("secret", "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef", "shared secret")
	flag.Parse()

	// Prepare the IP to connect to
	laddr, err := net.ResolveUDPAddr("udp", *localAddr)
	util.Check(err)

	listener, err := dtls.Listen("udp", laddr, &dtls.Config{LogAuthFail: func(*net.IP) { fmt.Println("err ip") }, LogOther: func(*net.IP) { fmt.Println("err other") }})
	if err != nil {
		fmt.Printf("error creating dtls listner: %v\n", err)
	}

	fmt.Println("Listening")

	// Simulate a chat session
	hub := util.NewHub()

	sharedSecret := []byte(*secret)
	go func() {
		for {
			// Wait for a connection.
			conn, err := listener.Accept(&dtls.Config{PSK: sharedSecret, SCTP: dtls.ServerAccept})
			util.Check(err)

			fmt.Println("new connection")
			// defer conn.Close() // TODO: graceful shutdown

			// `conn` is of type `net.Conn` but may be casted to `dtls.Conn`
			// using `dtlsConn := conn.(*dtls.Conn)` in order to to expose
			// functions like `ConnectionState` etc.

			// Register the connection with the chat hub
			hub.Register(conn)
		}
	}()

	// Start chatting
	hub.Chat()
}
