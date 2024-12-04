// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT
package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	golog "log"
	"net"
	"os"

	"github.com/pion/dtls/v2/examples/util"
	cj "github.com/refraction-networking/conjure/pkg/station/lib"
	"github.com/refraction-networking/conjure/pkg/station/log"
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

	fmt.Printf("%v\n", priv)

	logger := log.New(os.Stdout, "[oscur0] ", golog.Ldate|golog.Lmicroseconds)

	if err := oscur0.ListenAndProxy(addr,
		func(covert string, clientConn net.Conn) {
			fmt.Printf("got connection: %v -> %v, covert: %v\n", clientConn.LocalAddr(), clientConn.RemoteAddr(), covert)
			cj.ProxyNewTunStates(clientConn, logger, "", covert, false)
		}, oscur0.Config{PrivKey: priv}); err != nil {
		logger.Fatalf("error listening one-shot dtls: %v", err)
	}
}
