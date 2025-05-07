package ampCacheregserver

import (
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"

	"github.com/gorilla/mux"
	"github.com/refraction-networking/conjure/pkg/metrics"
	"github.com/refraction-networking/conjure/pkg/phantoms"
	"github.com/refraction-networking/conjure/pkg/regserver/regprocessor"
	pb "github.com/refraction-networking/conjure/proto"
	"github.com/sirupsen/logrus"
	log "github.com/sirupsen/logrus"
	"gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/snowflake/v2/common/amp"
	"google.golang.org/protobuf/proto"
)

type registrar interface {
	RegisterUnidirectional(*pb.C2SWrapper, pb.RegistrationSource, []byte) error
	RegisterBidirectional(*pb.C2SWrapper, pb.RegistrationSource, []byte) (*pb.RegistrationResponse, error)
}

type AMPCacheRegServer struct {
	apiPort          uint16
	ampCacheURL      string
	latestClientConf *pb.ClientConf // Latest clientConf for sharing over RegistrationResponse channel.
	ccMutex          sync.RWMutex
	processor        registrar
	logger           log.FieldLogger
	logClientIP      bool
	metrics          *metrics.Metrics
}

func (s *AMPCacheRegServer) getC2SFromReq(w http.ResponseWriter, r *http.Request, path string) (*pb.C2SWrapper, error) {
	const MinimumRequestLength = regprocessor.SecretLength + 1 // shared_secret + VSP
	if r.Method != "GET" {
		s.logger.Errorf("rejecting request due to incorrect method %s\n", r.Method)
		w.WriteHeader(http.StatusMethodNotAllowed)
		return nil, errors.New("incorrect method")
	}

	// path prefix, so this function unfortunately needs to be aware of and
	// remove its own routing prefix.
	if path == r.URL.Path {
		// The path didn't start with the expected prefix. This probably
		// indicates an internal bug.
		log.Println("ampC2SFromReq: unexpected prefix in path")
		w.WriteHeader(http.StatusInternalServerError)
		return nil, errors.New("Unexpected prefix in path")
	}

	var encRegistrationReq []byte
	var err error
	encRegistrationReq, err = amp.DecodePath(path)
	if err != nil {
		s.logger.Errorf("failed to read request body:", err)
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return nil, errors.New("failed to read request body")
	}
	if len(encRegistrationReq) < MinimumRequestLength {
		s.logger.Errorf("rejecting request due to short content-length of %d, expecting at least %d\n", len(encRegistrationReq), MinimumRequestLength)
		http.Error(w, "Payload too small", http.StatusBadRequest)
		return nil, errors.New("payload too small")
	}

	payload := &pb.C2SWrapper{}
	if err = proto.Unmarshal(encRegistrationReq, payload); err != nil {
		s.logger.Errorf("failed to decode protobuf body:", err)
		http.Error(w, "Failed to decode protobuf body", http.StatusBadRequest)
		return nil, errors.New("failed to decode protobuf body")
	}
	return payload, nil

}

func (s *AMPCacheRegServer) register(w http.ResponseWriter, r *http.Request) {
	s.metrics.Add("ampcache_requests_total", 1)
	logFields := log.Fields{"http_method": r.Method, "content_length": r.ContentLength, "registration_type": "unidirectional"}
	path := strings.TrimPrefix(r.URL.Path, "/amp/register/")
	reqLogger, payload, clientAddrBytes := s.registerCommon(logFields, path, w, r)
	if payload == nil || clientAddrBytes == nil {
		return
	}
	err := s.processor.RegisterUnidirectional(payload, pb.RegistrationSource_AMPCache, clientAddrBytes)

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	reqLogger.Debugf("registration successful")

	// We could send an HTTP response earlier to avoid waiting
	// while the zmq socket is locked, but this ensures that
	// a 204 truly indicates registration success.
	w.WriteHeader(http.StatusNoContent)
}

func (s *AMPCacheRegServer) registerBidirectional(w http.ResponseWriter, r *http.Request) {
	s.metrics.Add("bdampcache_requests_total", 1)

	logFields := log.Fields{"http_method": r.Method, "content_length": r.ContentLength, "registration_type": "bidirectional"}
	path := strings.TrimPrefix(r.URL.Path, "/amp/register-bidirectional/")
	reqLogger, payload, clientAddrBytes := s.registerCommon(logFields, path, w, r)
	if payload == nil || clientAddrBytes == nil {
		return
	}

	// Check server's client config -- add server's ClientConf if client is outdated
	serverClientConf := s.compareClientConfGen(payload.GetRegistrationPayload().GetDecoyListGeneration())
	if serverClientConf != nil {
		// Replace the payload generation with correct generation from server's client config
		payload.RegistrationPayload.DecoyListGeneration = serverClientConf.Generation
	}
	// Create registration response object
	regResp, err := s.processor.RegisterBidirectional(payload, pb.RegistrationSource_BidirectionalAMP, clientAddrBytes)

	if err != nil {
		switch err {
		case regprocessor.ErrNoC2SBody:
			http.Error(w, "no C2S body", http.StatusBadRequest)
		case phantoms.ErrLegacyMissingAddrs:
			fallthrough
		case phantoms.ErrLegacyV0SelectionBug:
			fallthrough
		case phantoms.ErrLegacyAddrSelectBug:
			http.Error(w, "bad seed", http.StatusBadRequest)
		default:
			reqLogger.Errorf("failed to create registration response: %v", err)
			w.WriteHeader(http.StatusInternalServerError)
		}
		return
	}

	if serverClientConf != nil {
		// Save the client config from server to return to client
		regResp.ClientConf = serverClientConf
	}

	w.Header().Set("Content-Type", "text/html")
	// Attempt to hint to an AMP cache not to waste resources caching this
	// document. "The Google AMP Cache considers any document fresh for at
	// least 15 seconds."
	// https://developers.google.com/amp/cache/overview#google-amp-cache-updates
	w.Header().Set("Cache-Control", "max-age=15")
	// Add header to w (server response)
	w.WriteHeader(http.StatusOK)
	// Marshal (serialize) registration response object and then write it to w
	body, err := proto.Marshal(regResp)
	if err != nil {
		reqLogger.Errorf("failed to write registration into response: %v", err)
		return
	}

	enc, err := amp.NewArmorEncoder(w)
	if err != nil {
		log.Printf("amp.NewArmorEncoder: %v", err)
		return
	}
	defer enc.Close()

	if _, err := enc.Write(body); err != nil {
		log.Printf("ampClientOffers: unable to write answer: %v", err)
	}

	reqLogger.Debugf("registration successful")

} // registerBidirectional()

func (s *AMPCacheRegServer) registerCommon(logFields log.Fields, path string, w http.ResponseWriter, r *http.Request) (*logrus.Entry, *pb.C2SWrapper, []byte) {
	reqLogger := s.logger.WithFields(logFields)
	reqLogger.Debugf("received new ampcache request")

	payload, err := s.getC2SFromReq(w, r, path)
	if err != nil {
		s.logger.Printf("Error with getC2SFromReq %v", err)
		return reqLogger, nil, nil
	}

	clientAddr := payload.RegistrationAddress
	if clientAddr == nil {
		reqLogger.Errorf("No client IP address received")
		return reqLogger, payload, nil
	}

	if s.logClientIP {
		logFields["ip_address"] = net.IP(clientAddr).String()
	}
	reqLogger = reqLogger.WithField("reg_id", hex.EncodeToString(payload.GetSharedSecret()))
	clientAddrBytes := []byte(net.IP(clientAddr).To16())
	return reqLogger, payload, clientAddrBytes

}

// Use this function in registerBidirectional, if the returned ClientConfig is
// not nil add it to the RegistrationResponse.
func (s *AMPCacheRegServer) compareClientConfGen(genNum uint32) *pb.ClientConf {
	s.ccMutex.RLock()
	defer s.ccMutex.RUnlock()

	// Check that server has a current (latest) client config
	if s.latestClientConf == nil {
		s.logger.Debugf("Server latest ClientConf is nil")
		return nil
	}

	s.logger.Debugf("client: %d, stored: %d\n", genNum, s.latestClientConf.GetGeneration())
	// Check if generation number param is greater than server's client config
	if genNum >= s.latestClientConf.GetGeneration() {
		return nil
	}

	// Otherwise, return server's client config
	s.metrics.Add("cc_updated", 1)
	return s.latestClientConf
}

func (s *AMPCacheRegServer) NewClientConf(c *pb.ClientConf) {
	if c != nil {
		s.ccMutex.Lock()
		defer s.ccMutex.Unlock()
		s.latestClientConf = c
	}
}

func (s *AMPCacheRegServer) ListenAndServe() error {
	r := mux.NewRouter()
	r.PathPrefix("/amp/register/").HandlerFunc(s.register)
	r.PathPrefix("/amp/register-bidirectional/").HandlerFunc(s.registerBidirectional)
	http.Handle("/amp/", r)

	log.Println("AMP cache reg server started")

	err := http.ListenAndServe(fmt.Sprintf(":%d", s.apiPort), nil)

	return err
}

func NewAMPCacheRegServer(apiPort uint16, ampCacheURL string, regprocessor *regprocessor.RegProcessor, latestCC *pb.ClientConf, logger log.FieldLogger, logClientIP bool, metrics *metrics.Metrics) (*AMPCacheRegServer, error) {
	if regprocessor == nil || latestCC == nil || logger == nil {
		return nil, errors.New("arguments cannot be nil")
	}
	return &AMPCacheRegServer{
		ampCacheURL:      ampCacheURL,
		apiPort:          apiPort,
		processor:        regprocessor,
		latestClientConf: latestCC,
		ccMutex:          sync.RWMutex{},
		logger:           logger,
		logClientIP:      logClientIP,
		metrics:          metrics,
	}, nil
}
