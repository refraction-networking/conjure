// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT
package main

import (
	"context"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"net"

	"github.com/pion/dtls/v2"
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

	// Prepare the configuration of the DTLS connection
	config := &dtls.Config{
		ConnectionIDGenerator: dtls.RandomCIDGenerator(cidSize),
		KeyLogWriter:          log.Default().Writer(),
	}

	priv, err := hex.DecodeString(station_privkey)
	util.Check(err)
	privkey := [32]byte{}
	n := copy(privkey[:], priv)
	if n != len(priv) {
		panic("wrong privkey size")
	}

	// Connect to a DTLS server
	listener, err := dtls.NewResumeListener("udp", addr, config)
	util.Check(err)
	defer func() {
		util.Check(listener.Close())
	}()

	fmt.Println("Listening")

	// Simulate a chat session
	hub := util.NewHub()

	go func() {
		for {
			// Wait for a connection.
			var pconn net.PacketConn
			pconn, addr, err := listener.Accept()
			util.Check(err)
			fmt.Printf("got connection: %v", addr)

			conn, info, err := oscur0.ServerWithContext(context.Background(), pconn, addr, oscur0.Config{PrivKey: privkey})
			util.Check(err)
			fmt.Printf("%+v\n", info)

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
