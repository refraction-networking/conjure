package dnsregserver

import (
	"encoding/hex"
	"errors"
	"fmt"
	"sync/atomic"

	"github.com/refraction-networking/conjure/pkg/log"
	"github.com/refraction-networking/conjure/pkg/metrics"
	"github.com/refraction-networking/conjure/pkg/registrars/dns-registrar/responder"
	"github.com/refraction-networking/conjure/pkg/regserver/regprocessor"
	pb "github.com/refraction-networking/conjure/proto"

	"google.golang.org/protobuf/proto"
)

type registrar interface {
	RegisterUnidirectional(*pb.C2SWrapper, pb.RegistrationSource, []byte) error
	RegisterBidirectional(*pb.C2SWrapper, pb.RegistrationSource, []byte) (*pb.RegistrationResponse, error)
}

// DNSRegServer provides an interface to forward DNS registration requests. Use a dns responder to receive requests and send responses.
type DNSRegServer struct {
	// dns responder to recieve and forward responses with
	dnsResponder *responder.Responder
	processor    registrar
	latestCCGen  uint32
	logger       *log.Logger
	metrics      *metrics.Metrics
}

// NewDNSRegServer creates a new DNSRegServer object.
func NewDNSRegServer(domain string, udpAddr string, privkey []byte, regprocessor *regprocessor.RegProcessor, latestClientConfGeneration uint32, logger *log.Logger, metrics *metrics.Metrics) (*DNSRegServer, error) {

	if domain == "" || udpAddr == "" || privkey == nil || regprocessor == nil || logger == nil {
		return nil, errors.New("all arguments must not be nil")
	}

	if len(privkey) < 32 {
		return nil, fmt.Errorf("Expected 32 byte privkey: got %d", len(privkey))
	}

	respder, err := responder.NewDnsResponder(domain, udpAddr, privkey[:32])
	if err != nil {
		return nil, fmt.Errorf("failed to create DNS responder: %v", err)
	}

	return &DNSRegServer{
		dnsResponder: respder,
		processor:    regprocessor,
		latestCCGen:  latestClientConfGeneration,
		logger:       logger,
		metrics:      metrics,
	}, nil
}

// ListenAndServe starts the DNS registration server.
func (s *DNSRegServer) ListenAndServe() error {
	err := s.dnsResponder.RecvAndRespond(s.processRequest)
	if err != nil {
		return errors.New("dns responder error: " + err.Error())
	}
	return nil
}

func (s *DNSRegServer) processRequest(reqIn []byte) ([]byte, error) {
	s.metrics.Add("dns_requests_total", 1)

	c2sPayload := &pb.C2SWrapper{}
	err := proto.Unmarshal(reqIn, c2sPayload)
	if err != nil {
		s.logger.Errorf("Error in received request unmarshal: [%v]", err)
		return nil, err
	}

	fields := fmt.Sprintf("reg_id: %s", hex.EncodeToString(c2sPayload.GetSharedSecret()))
	s.logger.Tracef("Request received: [%s] [%+v]", fields, c2sPayload)

	clientconfOutdated := false
	if c2sPayload.RegistrationPayload.GetDecoyListGeneration() < atomic.LoadUint32(&s.latestCCGen) {
		clientconfOutdated = true
	}

	dnsResp := &pb.DnsResponse{
		ClientconfOutdated: &clientconfOutdated,
	}

	reqIsBd := c2sPayload.GetRegistrationSource() == pb.RegistrationSource_BidirectionalDNS
	if reqIsBd {
		fields += fmt.Sprintf(", registration-type: bidirectional")
		var regResponse *pb.RegistrationResponse
		regResponse, err = s.processor.RegisterBidirectional(c2sPayload, pb.RegistrationSource_BidirectionalDNS, nil)
		dnsResp.BidirectionalResponse = regResponse
	} else {
		fields += fmt.Sprintf(", registration-type: unidirectional")
		err = s.processor.RegisterUnidirectional(c2sPayload, pb.RegistrationSource_DNS, nil)
	}

	// if registration publish failed, immediately return
	if err != nil {
		s.logger.Errorf("registration publish failed [%s]: %v", fields, err)
		regSuccess := false
		dnsResp.Success = &regSuccess

		failPayload, err := proto.Marshal(dnsResp)
		if err != nil {
			return nil, errors.New("response marshal failed")
		}
		return failPayload, nil
	}

	regSuccess := true
	dnsResp.Success = &regSuccess
	s.logger.Debugf("registration request successful [%s]", fields)
	responsePayload, err := proto.Marshal(dnsResp)
	if err != nil {
		s.logger.Errorf("response marshal failed, [%s]: %v", fields, err)
		return nil, errors.New("response marshal failed")
	}
	return responsePayload, nil
}

// Close closes the underlying dns responder.
func (s *DNSRegServer) Close() error {
	return s.dnsResponder.Close()
}

// UpdateLatestCCGen helps the DNS registration server to dynamically reload configuration, updating
// the latest client configuration generation number.
func (s *DNSRegServer) UpdateLatestCCGen(gen uint32) {
	atomic.StoreUint32(&s.latestCCGen, gen)
}
