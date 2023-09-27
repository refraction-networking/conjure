package utls

// func Test_generateKeyAndCert(t *testing.T) {
// 	// get our ca and server certificate
// 	serverTLSConf, clientTLSConf, err := certSetup()
// 	if err != nil {
// 		panic(err)
// 	}

// 	srv := &http.Server{
// 		TLSConfig:    &serverTLSConf,
// 		ReadTimeout:  time.Minute,
// 		WriteTimeout: time.Minute,
// 	}
// 	go func() {
// 		err := srv.ListenAndServeTLS("", "")
// 		if err != nil {
// 			t.Fail()
// 			return
// 		}
// 	}()

// 	// set up the httptest.Server using our certificate signed by our CA
// 	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
// 		fmt.Fprintln(w, "success!")
// 	}))
// 	server.TLS = serverTLSConf
// 	server.StartTLS()
// 	defer server.Close()

// 	// communicate with the server using an http.Client configured to trust our CA
// 	transport := &http.Transport{
// 		TLSClientConfig: clientTLSConf,
// 	}
// 	http := http.Client{
// 		Transport: transport,
// 	}
// 	resp, err := http.Get(server.URL)
// 	if err != nil {
// 		panic(err)
// 	}

// 	// verify the response
// 	respBodyBytes, err := ioutil.ReadAll(resp.Body)
// 	if err != nil {
// 		panic(err)
// 	}
// 	body := strings.TrimSpace(string(respBodyBytes[:]))
// 	require.Equal(t, "success!", body)
// }

// func readerFromKey(key [32]byte) io.Reader {
// 	hkdfReader := hkdf.New(sha256.New, key[:], []byte("cert testing string"), nil)
// 	return hkdfReader
// }

// func TestUTLSMakeConnWithCompleteHandshake(t *testing.T) {
// 	serverConn, clientConn := net.Pipe()

// 	masterSecret := []byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47}
// 	clientRandom := []byte{40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 70, 71}
// 	serverRandom := []byte{80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111}
// 	serverTlS := tls.MakeConnWithCompleteHandshake(serverConn, tls.VersionTLS12, tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
// 		masterSecret, clientRandom, serverRandom, false)
// 	clientTlS := tls.MakeConnWithCompleteHandshake(clientConn, tls.VersionTLS12, tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
// 		masterSecret, clientRandom, serverRandom, true)

// 	clientMsg := []byte("Hello, world!")
// 	serverMsg := []byte("Test response!")

// 	go func() {
// 		clientTlS.Write(clientMsg)
// 		resp := make([]byte, 20)
// 		read, err := clientTlS.Read(resp)
// 		if !bytes.Equal(resp[:read], serverMsg) {
// 			t.Errorf("client expected to receive: %v, got %v\n",
// 				serverMsg, resp[:read])
// 		}
// 		if err != nil {
// 			t.Errorf("error reading client: %+v\n", err)
// 		}
// 		clientConn.Close()
// 	}()

// 	buf := make([]byte, 20)
// 	read, err := serverTlS.Read(buf)
// 	if !bytes.Equal(buf[:read], clientMsg) {
// 		t.Errorf("server expected to receive: %v, got %v\n",
// 			clientMsg, buf[:read])
// 	}
// 	if err != nil {
// 		t.Errorf("error reading client: %+v\n", err)
// 	}

// 	serverTlS.Write(serverMsg)
// }

// func TestUTLSMakeConnWithCompleteHandshake(t *testing.T) {
// 	config := tls.Config{}
// 	clientCert, serverCert, err := certsFromSeed(config.PSK)
// 	require.Nil(t, err)

// }
