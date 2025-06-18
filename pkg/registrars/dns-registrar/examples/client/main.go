package main

import (
	"bufio"
	"encoding/hex"
	"flag"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/pion/dtls/v2/examples/util"
	"github.com/refraction-networking/conjure/pkg/registrars/dns-registrar/requester"
	"github.com/refraction-networking/conjure/pkg/registrars/dns-registrar/tworeqresp"
)

const key = "0b63baad7f2f4bb5b547c53adc0fbb179852910607935e6f4b5639fd989b1156"

func main() {
	var remoteAddr = flag.String("saddr", "127.0.0.1:6666", "remote address")
	var baseDomain = flag.String("domain", "test.xyz", "base domain to use")
	flag.Parse()

	addr, err := net.ResolveUDPAddr("udp", *remoteAddr)
	util.Check(err)

	pubKey, err := hex.DecodeString(key)
	util.Check(err)

	tworeq, err := tworeqresp.NewRequester(func() (tworeqresp.Onerequester, error) {
		return requester.NewRequester(&requester.Config{
			TransportMethod: requester.UDP,
			Target:          addr.String(),
			BaseDomain:      *baseDomain,
			Pubkey:          pubKey,
		})
	}, 80)
	util.Check(err)

	reader := bufio.NewReader(os.Stdin)

	fmt.Println("type 'exit' to shutdown gracefully")

	for {
		text, err := reader.ReadString('\n')
		util.Check(err)

		if strings.TrimSpace(text) == "exit" {
			return
		}

		resp, err := tworeq.RequestAndRecv([]byte(text))
		util.Check(err)

		fmt.Printf("Got message: %s\n", string(resp))

	}

}
