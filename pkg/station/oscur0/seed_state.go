package oscur0

import (
	"bytes"
	"crypto/sha256"
	"encoding/gob"
	"io"

	"github.com/pion/dtls/v2"
	"github.com/pion/dtls/v2/pkg/protocol/handshake"
	"golang.org/x/crypto/hkdf"
)

type serializedState struct {
	LocalEpoch            uint16
	RemoteEpoch           uint16
	LocalRandom           [handshake.RandomLength]byte
	RemoteRandom          [handshake.RandomLength]byte
	CipherSuiteID         uint16
	MasterSecret          []byte
	SequenceNumber        uint64
	SRTPProtectionProfile uint16
	PeerCertificates      [][]byte
	IdentityHint          []byte
	SessionID             []byte
	LocalConnectionID     []byte
	RemoteConnectionID    []byte
	IsClient              bool
}

func getDTLSStatePair(rand io.Reader) (*serializedState, *serializedState, error) {
	masterSecret := make([]byte, 48)
	clientSequenceNumber := make([]byte, 1)
	serverSequenceNumber := make([]byte, 1)
	clientCID := make([]byte, 8)
	serverCID := make([]byte, 8)

	if _, err := rand.Read(masterSecret); err != nil {
		return nil, nil, err
	}
	if _, err := rand.Read(clientSequenceNumber); err != nil {
		return nil, nil, err
	}
	if _, err := rand.Read(serverSequenceNumber); err != nil {
		return nil, nil, err
	}
	if _, err := rand.Read(clientCID); err != nil {
		return nil, nil, err
	}
	if _, err := rand.Read(serverCID); err != nil {
		return nil, nil, err
	}

	return &serializedState{
			LocalEpoch:         1,
			RemoteEpoch:        1,
			CipherSuiteID:      uint16(dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256),
			MasterSecret:       masterSecret,
			SequenceNumber:     uint64(clientSequenceNumber[0]),
			LocalConnectionID:  clientCID,
			RemoteConnectionID: serverCID,
			IsClient:           true,
		}, &serializedState{
			LocalEpoch:         1,
			RemoteEpoch:        1,
			CipherSuiteID:      uint16(dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256),
			MasterSecret:       masterSecret,
			SequenceNumber:     uint64(serverSequenceNumber[0]),
			LocalConnectionID:  serverCID,
			RemoteConnectionID: clientCID,
			IsClient:           false,
		}, nil
}

func DTLSClientState(seed []byte) (*dtls.State, error) {
	rand := hkdf.New(sha256.New, seed, nil, nil)

	state, _, err := getDTLSStatePair(rand)
	if err != nil {
		return nil, err
	}

	return toState(state)
}

func DTLSServerState(seed []byte) (*dtls.State, error) {
	rand := hkdf.New(sha256.New, seed, nil, nil)

	_, state, err := getDTLSStatePair(rand)
	if err != nil {
		return nil, err
	}

	return toState(state)
}

func toState(serialized *serializedState) (*dtls.State, error) {
	var buf bytes.Buffer
	enc := gob.NewEncoder(&buf)
	if err := enc.Encode(*serialized); err != nil {
		return nil, err
	}

	state := &dtls.State{}
	if err := state.UnmarshalBinary(buf.Bytes()); err != nil {
		return nil, err
	}

	return state, nil
}
