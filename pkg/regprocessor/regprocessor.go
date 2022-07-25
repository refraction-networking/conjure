package regprocessor

import (
	"encoding/binary"
	"errors"
	"sync"

	zmq "github.com/pebbe/zmq4"
	"github.com/refraction-networking/conjure/application/lib"
	pb "github.com/refraction-networking/gotapdance/protobuf"
	"google.golang.org/protobuf/proto"
)

var (
	ErrNoC2SBody    = errors.New("no C2S body")
	ErrNilC2S       = errors.New("C2S is nil")
	ErrSharedSecret = errors.New("shared secret undefined or insufficient length")
	ErrSelectIP     = errors.New("failed to select IP")
	ErrGenSharedKey = errors.New("failed to generate shared key")
	ErrZmqSocket    = errors.New("failed to create zmq socket")
	ErrRegPubFailed = errors.New("failed to publish to registration")
)

const (
	// The length of the shared secret sent by the client in bytes.
	regIDLen = 16

	// SecretLength gives the length of a secret (used for minimum registration body len)
	SecretLength = 32
)

// RegProcessor provides an interface to publish registrations and helper functions to process registration requests
type RegProcessor struct {
	sync.Mutex
	ipSelector lib.PhantomIPSelector
	sock       *zmq.Socket

	// Function to accept message into processing queue.
	// Abstracted to allow mocking of ZMQ send flow
	messageAccepter func([]byte) error
}

// NewRegProcessor initialize a new RegProcessor
func NewRegProcessor(zmqBindAddr string, zmqPort uint16, privkey string, authVerbose bool) (*RegProcessor, error) {
	s := &RegProcessor{}
	s.ipSelector = *lib.NewRegistrationManager().PhantomSelector
	sock, err := zmq.NewSocket(zmq.PUB)
	if err != nil {
		return nil, ErrZmqSocket
	}
	s.sock = sock
	s.messageAccepter = s.sendToZMQ
	return s, nil
}

// sendToZMQ sends registration message to zmq
func (s *RegProcessor) sendToZMQ(message []byte) error {
	s.Lock()
	_, err := s.sock.SendBytes(message, zmq.DONTWAIT)
	s.Unlock()

	return err
}

// RegisterUnidirectional process a unidirectional registration request and publish it to zmq
func (p *RegProcessor) RegisterUnidirectional(c2sPayload *pb.C2SWrapper, clientAddr []byte, regMethod pb.RegistrationSource) error {
	zmqPayload, err := processC2SWrapper(c2sPayload, clientAddr, regMethod)
	if err != nil {
		return err
	}

	err = p.sendToZMQ(zmqPayload)
	if err != nil {
		return ErrRegPubFailed
	}

	return nil
}

// RegisterUnidirectional process a bidirectional registration request, publish it to zmq, and returns a response
func (p *RegProcessor) RegisterBidirectional(c2sPayload *pb.C2SWrapper, regMethod pb.RegistrationSource, clientAddr []byte) (*pb.RegistrationResponse, error) {
	regResp, err := p.processBdReq(c2sPayload)
	if err != nil {
		return nil, err
	}

	zmqPayload, err := processC2SWrapper(c2sPayload, clientAddr, regMethod)
	if err != nil {
		return nil, err
	}

	err = p.sendToZMQ(zmqPayload)
	if err != nil {
		return nil, ErrRegPubFailed
	}

	return regResp, nil

}

// processBdReq reads a bidirectional request, generates phantom IPs, and returns a registration response for the client that has the ip filled out
func (p *RegProcessor) processBdReq(c2sPayload *pb.C2SWrapper) (*pb.RegistrationResponse, error) {
	// Create registration response object
	regResp := &pb.RegistrationResponse{}

	if c2sPayload.GetRegistrationPayload() == nil {
		return nil, ErrNoC2SBody
	}

	clientLibVer := uint(c2sPayload.GetRegistrationPayload().GetClientLibVersion())

	// Generate seed and phantom address
	cjkeys, err := lib.GenSharedKeys(c2sPayload.SharedSecret)

	if err != nil {
		// p.logger.Println("Failed to generate the shared key using SharedSecret:", err)
		return nil, ErrGenSharedKey
	}

	if *c2sPayload.RegistrationPayload.V4Support {
		phantom4, err := p.ipSelector.Select(
			cjkeys.DarkDecoySeed,
			uint(c2sPayload.GetRegistrationPayload().GetDecoyListGeneration()), //generation type uint
			clientLibVer,
			false,
		)

		if err != nil {
			// p.logger.Println("Failed to select IPv4Address:", err)
			return nil, ErrSelectIP
		}

		addr4 := binary.BigEndian.Uint32(phantom4.To4())
		regResp.Ipv4Addr = &addr4
	}

	if *c2sPayload.RegistrationPayload.V6Support {
		phantom6, err := p.ipSelector.Select(
			cjkeys.DarkDecoySeed,
			uint(c2sPayload.GetRegistrationPayload().GetDecoyListGeneration()),
			clientLibVer,
			true,
		)
		if err != nil {
			// p.logger.Println("Failed to select IPv6Address:", err)
			return nil, ErrSelectIP
		}

		regResp.Ipv6Addr = phantom6
	}

	port := uint32(443)
	regResp.Port = &port // future  -change to randomized

	return regResp, nil
}

// processC2SWrapper adds missing variables to the input c2s and returns the payload in format ready to be published to zmq
func processC2SWrapper(c2sPayload *pb.C2SWrapper, clientAddr []byte, regMethod pb.RegistrationSource) ([]byte, error) {
	payload := &pb.C2SWrapper{}

	if c2sPayload == nil {
		return nil, ErrNilC2S
	}

	if len(c2sPayload.GetSharedSecret()) < regIDLen/2 {
		return nil, ErrSharedSecret
	}

	// If the channel that the registration was received over was not specified
	// in the C2SWrapper set it here as API.
	if c2sPayload.GetRegistrationSource() == pb.RegistrationSource_Unspecified {
		source := regMethod
		payload.RegistrationSource = &source
	} else {
		source := c2sPayload.GetRegistrationSource()
		payload.RegistrationSource = &source
	}

	// If the address that the registration was received from was NOT set in the
	// C2SWrapper set it here to the source address of the API (uni or bidirectional) request.
	if c2sPayload.GetRegistrationAddress() == nil ||
		c2sPayload.GetRegistrationSource() == regMethod {
		payload.RegistrationAddress = clientAddr
	} else {
		payload.RegistrationAddress = c2sPayload.GetRegistrationAddress()
	}

	payload.SharedSecret = c2sPayload.GetSharedSecret()
	payload.RegistrationPayload = c2sPayload.GetRegistrationPayload()

	// s.logger.Printf("forwarding registration %s source %v \n", hex.EncodeToString(payload.GetSharedSecret())[:regIDLen], payload.GetRegistrationSource())
	return proto.Marshal(payload)
}
