package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"net"

	"github.com/pion/dtls/v2/examples/util"
	"github.com/refraction-networking/conjure/pkg/registrars/dns-registrar/responder"
	"github.com/refraction-networking/conjure/pkg/registrars/dns-registrar/tworeqresp"
)

const key = "203963feed62ddda89b98857940f09866ae840f42e8c90160e411a0029b87e60"

func main() {
	var localAddr = flag.String("laddr", "[::]:6666", "source address")
	var domain = flag.String("domain", "test.xyz", "domain to use")
	var msg = flag.String("msg", "hey", "message to respond")
	flag.Parse()

	privKey, err := hex.DecodeString(key)
	util.Check(err)

	// Prepare the IP to connect to
	laddr, err := net.ResolveUDPAddr("udp", *localAddr)
	util.Check(err)

	responder, err := responder.NewDnsResponder(*domain, laddr.String(), privKey)
	util.Check(err)

	tworesponder, err := tworeqresp.NewResponder(responder)
	util.Check(err)

	fmt.Println("Listening")

	tworesponder.RecvAndRespond(func(b []byte) ([]byte, error) {
		fmt.Println(string(b))
		return []byte(*msg), nil
	})

}
