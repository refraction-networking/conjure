package main

import (
	"io"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	cj "github.com/refraction-networking/conjure/application/lib"
)

// MockGeoIP is a mock implementation of the geoip.GeoIP interface.
type MockGeoIP struct{}

// CC is a mock implementation of the CC method.
func (m *MockGeoIP) CC(ip net.IP) (string, error) {
	// Return a dummy country code for testing valid CC behavior
	return "US", nil

	// Return "" for testing empty db or non-nil error in CC behavior
	// return "", nil

	// Return "unk" for testing unknown CC behavior (nil error)
	// return "unk", nil
}

// ASN is a mock implementation of the ASN method.
func (m *MockGeoIP) ASN(ip net.IP) (uint, error) {
	// Return a dummy ASN for testing valid ASN behavior
	return 12345, nil

	// Return 0 for testing empty db or invalid ASN behavior
	// return 0, nil
}

func TestHandleNewTCPConn(t *testing.T) {
	testSubnetPath := os.Getenv("GOPATH") + "/src/github.com/refraction-networking/conjure/application/lib/test/phantom_subnets.toml"
	os.Setenv("PHANTOM_SUBNET_LOCATION", testSubnetPath)

	rm := cj.NewRegistrationManager(&cj.RegConfig{})

	db := &MockGeoIP{}
	rm.GeoIP = db

	connManager := newConnManager(nil)
	ip := net.ParseIP("8.8.8.8")
	clientConn, serverConn := net.Pipe()

	// Create a WaitGroup to synchronize the test execution
	var wg sync.WaitGroup
	wg.Add(1)

	// Call the handleNewTCPConn function in a separate goroutine
	go func() {
		connManager.handleNewTCPConn(rm, clientConn, ip)
		wg.Done()
	}()

	// Simulate sending data from the client to the server
	clientData := []byte("Hello, server!")
	go func() {
		// Add a small delay before writing data to allow handleNewTCPConn to start reading
		time.Sleep(200 * time.Millisecond)
		_, err := serverConn.Write([]byte("Hello, server!"))
		if err != nil {
			t.Errorf("failed to write data to server: %v", err)
		}
	}()

	// Simulate receiving data from the server
	serverData := make([]byte, len(clientData))
	_, err := io.ReadFull(clientConn, serverData)
	if err != nil {
		t.Fatalf("failed to read data from server: %v", err)
	}

	// Verify that the server received the correct data
	if string(serverData) != string(clientData) {
		t.Errorf("unexpected data received by the server: got %q, want %q", serverData, clientData)
	}

	// Close the server connection
	serverConn.Close()

	// Wait for the handleNewTCPConn function to finish processing
	wg.Wait()

	// Close the client connection
	clientConn.Close()
}
