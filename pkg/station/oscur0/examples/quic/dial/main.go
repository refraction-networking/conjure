package main

import (
	"context"
	"flag"
	"fmt"
	"net"

	"github.com/pion/dtls/v2/examples/util"
	quic "github.com/refraction-networking/uquic"
	tls "github.com/refraction-networking/utls"
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
	quicSpec, err := quic.QUICID2Spec(quic.QUICFirefox_116)
	util.Check(err)
	for _, ext := range quicSpec.ClientHelloSpec.Extensions {
		if ks, ok := ext.(*tls.KeyShareExtension); ok {
			ks.KeyShares = []tls.KeyShare{
				{
					Group: tls.X25519Kyber768Draft00,
					Data:  []byte{},
				},
			}
			break
		}
	}

	tp := quic.UTransport{
		Transport: &quic.Transport{
			Conn: pconn,
		},
		QUICSpec: &quicSpec,
	}

	// tp := &quic.Transport{
	// 	Conn: pconn,
	// }

	// econn1, err := tp.DialEarly(context.Background(), addr, &tls.Config{
	// 	InsecureSkipVerify: true,
	// 	NextProtos:         []string{"h3"},
	// }, &quic.Config{})
	// util.Check(err)
	// _ = econn1

	econn, err := tp.DialEarly(context.Background(), addr, &tls.Config{
		InsecureSkipVerify: true,
		// CurvePreferences:   []tls.CurveID{tls.X25519Kyber768Draft00},
		NextProtos: []string{"h3"},
	}, &quic.Config{})
	util.Check(err)

	stream, err := econn.OpenStream()
	util.Check(err)

	stream2, err := econn.OpenStream()
	util.Check(err)

	fmt.Println("Connected; type 'exit' to shutdown gracefully")

	stream2.Write([]byte("testt\n"))

	// Simulate a chat session
	util.Chat(stream)

}
