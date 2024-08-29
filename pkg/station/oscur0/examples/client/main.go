package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"net"
	"sync"

	"github.com/pion/dtls/v2/examples/util"
	"github.com/refraction-networking/conjure/pkg/station/oscur0"
	"github.com/refraction-networking/gotapdance/tapdance"
)

func main() {
	var remoteAddr = flag.String("saddr", "127.0.0.1:6666", "remote address")
	// var localAddr = flag.String("laddr", "", "source address")
	var pubkey = flag.String("secret", "0b63baad7f2f4bb5b547c53adc0fbb179852910607935e6f4b5639fd989b1156", "shared secret")
	var covert = flag.String("covert", "1.2.3.4:5678", "covert address")
	var localPort = flag.Int("localPort", 10500, "port to listen on")
	flag.Parse()
	// Prepare the IP to connect to
	// laddr, err := net.ResolveUDPAddr("udp", *localAddr)
	// util.Check(err)

	addr, err := net.ResolveUDPAddr("udp", *remoteAddr)
	util.Check(err)

	pubkeyBytes, err := hex.DecodeString(*pubkey)
	util.Check(err)

	fmt.Printf("pubkey: %+v\n", pubkeyBytes)

	conn, err := oscur0.Dial(addr, oscur0.Config{Phantom: *covert, PubKey: pubkeyBytes})
	util.Check(err)

	if err := connectOscur0(*covert, *localPort, conn); err != nil {
		util.Check(err)
	}

}

func connectOscur0(covert string, localPort int, tdConn net.Conn) error {
	if _, _, err := net.SplitHostPort(covert); err != nil {
		return fmt.Errorf("failed to parse host and port from connectTarget %s: %v",
			covert, err)

	}

	l, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: localPort})
	if err != nil {
		return fmt.Errorf("error listening on port %v: %v", localPort, err)
	}

	clientConn, err := l.AcceptTCP()
	if err != nil {
		return err
	}

	proxy(tdConn, clientConn)

	return nil
}

func proxy(tdConn net.Conn, clientConn *net.TCPConn) {
	// Copy data from the client application into the DarkDecoy connection.
	// 		TODO: proper connection management with idle timeout
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		io.Copy(tdConn, clientConn)
		wg.Done()
		tdConn.Close()
	}()
	go func() {
		io.Copy(clientConn, tdConn)
		wg.Done()
		clientConn.CloseWrite()
	}()
	wg.Wait()
	tapdance.Logger().Debug("copy loop ended")
}
