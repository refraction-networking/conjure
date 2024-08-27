package oscur0

import (
	"bytes"
	"net"
	"testing"
)

var pubkey = []byte{11, 99, 186, 173, 127, 47, 75, 181, 181, 71, 197, 58, 220, 15, 187, 23, 152, 82, 145, 6, 7, 147, 94, 111, 75, 86, 57, 253, 152, 155, 17, 86}
var privkey = []byte{32, 57, 99, 254, 237, 98, 221, 218, 137, 185, 136, 87, 148, 15, 9, 134, 106, 232, 64, 244, 46, 140, 144, 22, 14, 65, 26, 0, 41, 184, 126, 96}

func TestConn(t *testing.T) {

	addr := &net.UDPAddr{IP: []byte{127, 0, 0, 1}, Port: 1234}
	phantom := "1.2.3.4:1234"
	send := []byte("hi")
	resp := []byte("hey")

	listener, err := Listen(addr, Config{PrivKey: privkey})
	if err != nil {
		t.Fatalf("error creatign listener: %v", err)
	}

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			t.Fatalf("error listening conn: %v", err)
		}

		readBuf := make([]byte, len(send))

		if _, err := conn.Read(readBuf); err != nil {
			t.Fatalf("error reading buffer: %v", err)
		}

		if !bytes.Equal(readBuf, send) {
			t.Fatalf("sent bytes != received")
		}

		if _, err := conn.Write(resp); err != nil {
			t.Fatalf("error writing resp: %v", err)
		}

	}()

	conn, err := Dial(addr, Config{PubKey: pubkey, Phantom: phantom})
	if err != nil {
		t.Fatalf("error creating client conn: %v", err)
	}

	if _, err := conn.Write(send); err != nil {
		t.Fatalf("error writing send: %v", err)
	}

	readBuf := make([]byte, len(resp))

	if _, err := conn.Read(readBuf); err != nil {
		t.Fatalf("error reading buffer: %v", err)
	}

	if !bytes.Equal(readBuf, resp) {
		t.Fatalf("sent bytes != received")
	}

}
