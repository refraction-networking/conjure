package oscur0

var privkey = "203963feed62ddda89b98857940f09866ae840f42e8c90160e411a0029b87e60"

// func TestConn(t *testing.T) {
// 	makePipe := func() (c1, c2 net.Conn, stop func(), err error) {
// 		privkeyBytes := hex.DecodeString(privkey)
// 		server, client := net.Pipe()
// 		s, err := Server(dtlsnet.PacketConnFromConn(server), server.RemoteAddr(), &Config{})
// 		if err != nil {
// 			t.Fatalf("error creating server: %v", err)
// 		}

// 		c, err := (dtlsnet.PacketConnFromConn(client), )
// 	}

// }
