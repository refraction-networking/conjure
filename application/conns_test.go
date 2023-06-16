package main

import (
	"io"
	"net"
	"os"
	"testing"

	cj "github.com/refraction-networking/conjure/application/lib"
)

func TestHandleNewTCPConn(t *testing.T) {
	// testSubnetPath := os.Getenv("GOPATH") + "/src/github.com/refraction-networking/conjure/application/lib/test/phantom_subnets.toml"
	testSubnetPath := "/mnt/c/Users/Anisha/Desktop/Refraction Networking/conjure/application/lib/test/phantom_subnets.toml"
	os.Setenv("PHANTOM_SUBNET_LOCATION", testSubnetPath)

	rm := cj.NewRegistrationManager(&cj.RegConfig{})
	connManager := newConnManager(nil)
	ip := net.ParseIP("8.8.8.8")
	clientConn, serverConn := net.Pipe()

	// Call the handleNewTCPConn function in a separate goroutine
	go connManager.handleNewTCPConn(rm, clientConn, ip)

	// Simulate sending data from the client to the server
	clientData := []byte("Hello, server!")
	go func() {
		_, err := serverConn.Write([]byte("Hello, server!"))
		if err != nil {
			t.Fatalf("failed to write data to server: %v", err)
		}
	}()
	// clientData := []byte("Hello, server!")
	// _, err := serverConn.Write(clientData)
	// if err != nil {
	// 	t.Fatalf("failed to write data to server: %v", err)
	// }

	// Simulate receiving data from the server
	serverData := make([]byte, len(clientData))
	_, err := io.ReadFull(clientConn, serverData)
	if err != nil {
		t.Fatalf("failed to read data from server: %v", err)
	}
	// serverData := make([]byte, len(clientData))
	// _, err = io.ReadFull(clientConn, serverData)
	// if err != nil {
	// 	t.Fatalf("failed to read data from server: %v", err)
	// }

	// Verify that the server received the correct data
	if string(serverData) != string(clientData) {
		t.Errorf("unexpected data received by the server: got %q, want %q", serverData, clientData)
	}

	// Close the client and server connections
	clientConn.Close()
	serverConn.Close()

	// connManager.handleNewTCPConn(rm, client, ip)
}
