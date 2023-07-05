package main

import (
	"fmt"
	"io"
	"io/ioutil"
	golog "log"
	"math"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/refraction-networking/conjure/internal/conjurepath"
	cj "github.com/refraction-networking/conjure/pkg/station/lib"
	"github.com/refraction-networking/conjure/pkg/station/log"
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

func TestConnHandleNewTCPConn(t *testing.T) {
	testSubnetPath := conjurepath.Root + "/pkg/station/lib/test/phantom_subnets.toml"
	os.Setenv("PHANTOM_SUBNET_LOCATION", testSubnetPath)

	rm := cj.NewRegistrationManager(&cj.RegConfig{})

	db := &MockGeoIP{}
	rm.GeoIP = db

	connManager := newConnManager(nil)
	ip := net.ParseIP("8.8.8.8")
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	// Create a WaitGroup to synchronize the test execution
	var wg sync.WaitGroup
	wg.Add(1)

	// Call the handleNewTCPConn function in a separate goroutine
	go func() {
		connManager.handleNewTCPConn(rm, serverConn, ip)
		wg.Done()
	}()

	// Simulate sending data from the client to the server
	clientData := []byte("Hello, server!")
	go func() {
		// Add a small delay before writing data to allow handleNewTCPConn to start reading
		time.Sleep(200 * time.Millisecond)
		_, err := clientConn.Write([]byte("Hello, server!"))
		if err != nil {
			t.Errorf("failed to write data to server: %v", err)
		}
	}()

	// Simulate receiving data from the server
	serverData := make([]byte, len(clientData))
	_, err := io.ReadFull(serverConn, serverData)
	if err != nil {
		t.Fatalf("failed to read data from server: %v", err)
	}

	// Verify that the server received the correct data
	if string(serverData) != string(clientData) {
		t.Errorf("unexpected data received by the server: got %q, want %q", serverData, clientData)
	}

	// Wait for the handleNewTCPConn function to finish processing
	wg.Wait()
}

func TestConnPrintAndReset(t *testing.T) {
	logger := log.New(os.Stdout, "[TEST CONN STATS] ", golog.Ldate|golog.Lmicroseconds)
	connManager := newConnManager(nil)
	newGeoIPMap := make(map[uint]*asnCounts)
	newGeoIPMap[0] = &asnCounts{
		cc: "unk",
		statCounts: statCounts{
			numCreatedToDiscard: 1,
			numCreatedToCheck:   2,
			numCreatedToReset:   3,
			numCreatedToTimeout: 4,
			numCreatedToError:   5,
		},
	}
	newGeoIPMap[1] = &asnCounts{
		cc: "US",
		statCounts: statCounts{
			numCreatedToDiscard: 6,
			numCreatedToCheck:   7,
			numCreatedToReset:   8,
			numCreatedToTimeout: 9,
			numCreatedToError:   10,
			totalTransitions:    2,
		},
	}
	connManager.connStats.numCreated = 55
	connManager.connStats.numCheckToError = 1
	connManager.connStats.numReset = 17
	connManager.connStats.geoIPMap = newGeoIPMap
	connManager.connStats.PrintAndReset(logger)
}

func TestConnHandleConcurrent(t *testing.T) {
	// We don't actually care about what gets written
	logger := log.New(ioutil.Discard, "[TEST CONN STATS] ", golog.Ldate|golog.Lmicroseconds)

	testSubnetPath := conjurepath.Root + "/pkg/station/lib/test/phantom_subnets.toml"
	os.Setenv("PHANTOM_SUBNET_LOCATION", testSubnetPath)

	rm := cj.NewRegistrationManager(&cj.RegConfig{})

	db := &MockGeoIP{}
	rm.GeoIP = db

	connManager := newConnManager(nil)

	go func() {
		// continuously print to force race condition
		for {
			connManager.connStats.PrintAndReset(logger)
		}
	}()
	// Create a WaitGroup to synchronize the test execution
	var wg sync.WaitGroup

	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			ip := net.ParseIP("8.8.8.8")
			clientConn, serverConn := net.Pipe()
			defer clientConn.Close()
			defer serverConn.Close()

			// Call the handleNewTCPConn function in a separate goroutine
			go func() {
				connManager.handleNewTCPConn(rm, serverConn, ip)
				wg.Done()
			}()

			// Simulate sending data from the client to the server
			clientData := []byte("Hello, server!")
			go func() {
				// Add a small delay before writing data to allow handleNewTCPConn to start reading
				time.Sleep(200 * time.Millisecond)
				_, err := clientConn.Write([]byte("Hello, server!"))
				if err != nil {
					t.Errorf("failed to write data to server: %v", err)
				}
			}()

			// Simulate receiving data from the server
			serverData := make([]byte, len(clientData))
			_, err := io.ReadFull(serverConn, serverData)
			if err != nil {
				t.Logf("failed to read data from server: %v", err)
				t.Fail()
			}

			// Verify that the server received the correct data
			if string(serverData) != string(clientData) {
				t.Errorf("unexpected data received by the server: got %q, want %q", serverData, clientData)
			}
		}()
	}

	// Wait for the handleNewTCPConn function to finish processing
	wg.Wait()
}

func TestConnForceRace(t *testing.T) {
	// We don't actually care about what gets written
	logger := log.New(ioutil.Discard, "[TEST CONN STATS] ", golog.Ldate|golog.Lmicroseconds)
	cs := &connStats{geoIPMap: make(map[uint]*asnCounts)}
	exit := make(chan struct{})

	go func() {
		// continuously print until we receive the exit signal to force race condition
		for {
			select {
			case <-exit:
				break
			default:
				cs.PrintAndReset(logger)
			}
		}
	}()

	var wg sync.WaitGroup
	for i := 1; i <= 10; i++ {
		wg.Add(1)
		go func(il int) {
			for j := 0; j < 10; j++ {
				im := int(math.Max(float64(il), 1)) // prevent div by 0
				asn := uint(j % im)
				cc := fmt.Sprintf("%d", uint(j/im))
				cs.addCreated(asn, cc)
				cs.createdToDiscard(asn, cc)
				cs.createdToCheck(asn, cc)
				cs.createdToReset(asn, cc)
				cs.createdToTimeout(asn, cc)
				cs.createdToError(asn, cc)
				cs.readToCheck(asn, cc)
				cs.readToTimeout(asn, cc)
				cs.readToReset(asn, cc)
				cs.readToError(asn, cc)
				cs.checkToCreated(asn, cc)
				cs.checkToRead(asn, cc)
				cs.checkToFound(asn, cc)
				cs.checkToError(asn, cc)
				cs.checkToDiscard(asn, cc)
				cs.discardToReset(asn, cc)
				cs.discardToTimeout(asn, cc)
				cs.discardToError(asn, cc)
				cs.discardToClose(asn, cc)
			}
			wg.Done()
		}(i)
	}

	wg.Wait()
	close(exit)
}
