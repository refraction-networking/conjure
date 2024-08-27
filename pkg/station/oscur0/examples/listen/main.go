// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT
package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"net"

	"github.com/pion/dtls/v2/examples/util"
	"github.com/refraction-networking/conjure/pkg/station/oscur0"
)

const (
	receiveMTU      = 8192
	cidSize         = 8
	keySize         = 32
	station_privkey = "203963feed62ddda89b98857940f09866ae840f42e8c90160e411a0029b87e60"
)

func main() {
	var listenAddr = flag.String("laddr", "0.0.0.0:6666", "listen address")

	flag.Parse()

	// Prepare the IP to connect to
	addr, err := net.ResolveUDPAddr("udp", *listenAddr)
	util.Check(err)

	priv, err := hex.DecodeString(station_privkey)
	util.Check(err)
	privkey := [32]byte{}
	n := copy(privkey[:], priv)
	if n != len(priv) {
		panic("wrong privkey size")
	}

	listener, err := oscur0.Listen(addr, oscur0.Config{PrivKey: privkey})
	util.Check(err)

	// Simulate a chat session
	hub := util.NewHub()

	go func() {
		for {
			// Wait for a connection.
			conn, err := listener.Accept()
			util.Check(err)
			fmt.Printf("covert: %v\n", conn.Covert())

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
