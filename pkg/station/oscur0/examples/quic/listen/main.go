// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT
package main

import (
	"context"
	"crypto/tls"
	"encoding/hex"
	"flag"
	"fmt"
	"net"

	"github.com/pion/dtls/v2/examples/util"
	"github.com/quic-go/quic-go"
)

const (
	receiveMTU      = 8192
	cidSize         = 8
	keySize         = 32
	station_privkey = "203963feed62ddda89b98857940f09866ae840f42e8c90160e411a0029b87e60"
)

type streamConn struct {
	quic.Stream
	quic.Connection
}

func main() {
	var listenAddr = flag.String("laddr", "0.0.0.0:6666", "listen address")

	flag.Parse()

	// Prepare the IP to connect to
	addr, err := net.ResolveUDPAddr("udp", *listenAddr)
	util.Check(err)

	priv, err := hex.DecodeString(station_privkey)
	util.Check(err)

	fmt.Printf("%v\n", priv)

	pconn, err := net.ListenUDP("udp", addr)
	util.Check(err)
	tp := quic.Transport{
		Conn: pconn,
	}

	listener, err := tp.ListenEarly(&tls.Config{InsecureSkipVerify: true}, &quic.Config{})
	util.Check(err)

	// Simulate a chat session
	hub := util.NewHub()

	go func() {
		for {
			// Wait for a connection.
			econn, err := listener.Accept(context.Background())
			util.Check(err)

			stream, err := econn.AcceptStream(context.Background())
			util.Check(err)

			// `conn` is of type `net.Conn` but may be casted to `dtls.Conn`
			// using `dtlsConn := conn.(*dtls.Conn)` in order to to expose
			// functions like `ConnectionState` etc.

			// Register the connection with the chat hub
			hub.Register(&streamConn{Stream: stream, Connection: econn})
		}
	}()

	// Start chatting
	hub.Chat()
}
