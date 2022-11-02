package apiregserver

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"

	"github.com/gorilla/mux"
	"github.com/refraction-networking/conjure/pkg/metrics"
	"github.com/refraction-networking/conjure/pkg/regprocessor"
	pb "github.com/refraction-networking/gotapdance/protobuf"
	log "github.com/sirupsen/logrus"
	"google.golang.org/protobuf/proto"
)

type registrar interface {
	RegisterUnidirectional(*pb.C2SWrapper, pb.RegistrationSource, []byte) error
	RegisterBidirectional(*pb.C2SWrapper, pb.RegistrationSource, []byte) (*pb.RegistrationResponse, error)
}

type APIRegServer struct {
	apiPort          uint16
	latestClientConf *pb.ClientConf // Latest clientConf for sharing over RegistrationResponse channel.
	ccMutex          sync.RWMutex
	processor        registrar
	logger           log.FieldLogger
	logClientIP      bool
	metrics          *metrics.Metrics
}

// Get the first element of the X-Forwarded-For header if it is available, this
// will be the clients address if intermediate proxies follow X-Forwarded-For
// specification (as seen here: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Forwarded-For).
// Otherwise return the remote address specified in the request.
//
// In the future this may need to handle True-Client-IP headers.
func getRemoteAddr(r *http.Request) string {
	if r.Header.Get("X-Forwarded-For") != "" {
		addrList := r.Header.Get("X-Forwarded-For")
		return strings.Trim(strings.Split(addrList, ",")[0], " \t")
	}
	return r.RemoteAddr
}

func (s *APIRegServer) getC2SFromReq(w http.ResponseWriter, r *http.Request) (*pb.C2SWrapper, error) {
	const MinimumRequestLength = regprocessor.SecretLength + 1 // shared_secret + VSP
	if r.Method != "POST" {
		s.logger.Errorf("rejecting request due to incorrect method %s\n", r.Method)
		w.WriteHeader(http.StatusMethodNotAllowed)
		return nil, errors.New("incorrect method")
	}

	if r.ContentLength < MinimumRequestLength {
		s.logger.Errorf("rejecting request due to short content-length of %d, expecting at least %d\n", r.ContentLength, MinimumRequestLength)
		http.Error(w, "Payload too small", http.StatusBadRequest)
		return nil, errors.New("payload too small")
	}

	in, err := io.ReadAll(r.Body)
	if err != nil {
		s.logger.Errorf("failed to read request body:", err)
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return nil, errors.New("failed to read request body")
	}

	payload := &pb.C2SWrapper{}
	if err = proto.Unmarshal(in, payload); err != nil {
		s.logger.Errorf("failed to decode protobuf body:", err)
		http.Error(w, "Failed to decode protobuf body", http.StatusBadRequest)
		return nil, errors.New("failed to decode protobuf body")
	}

	return payload, nil
}

func (s *APIRegServer) register(w http.ResponseWriter, r *http.Request) {
	s.metrics.Add("api_requests_total", 1)

	requestIP := getRemoteAddr(r)

	logFields := log.Fields{"http_method": r.Method, "content_length": r.ContentLength, "registration_type": "unidirectional"}
	if s.logClientIP {
		logFields["ip_address"] = requestIP
	}
	reqLogger := s.logger.WithFields(logFields)

	reqLogger.Debugf("recived new request")

	payload, err := s.getC2SFromReq(w, r)
	if err != nil {
		reqLogger.Errorf("registration failed: %v", err)
		return
	}

	reqLogger = reqLogger.WithField("reg_id", hex.EncodeToString(payload.GetSharedSecret()))

	clientAddr := parseIP(requestIP)
	var clientAddrBytes = make([]byte, 16)
	if clientAddr != nil {
		clientAddrBytes = []byte(clientAddr.To16())
	}

	err = s.processor.RegisterUnidirectional(payload, pb.RegistrationSource_API, clientAddrBytes)

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

func (s *APIRegServer) registerBidirectional(w http.ResponseWriter, r *http.Request) {
	s.metrics.Add("bdapi_requests_total", 1)
	requestIP := getRemoteAddr(r)

	logFields := log.Fields{"http_method": r.Method, "content_length": r.ContentLength, "registration_type": "bidirectional"}
	if s.logClientIP {
		logFields["ip_address"] = requestIP
	}
	reqLogger := s.logger.WithFields(logFields)

	reqLogger.Debugf("recived new request")

	payload, err := s.getC2SFromReq(w, r)
	if err != nil {
		return
	}

	reqLogger = reqLogger.WithField("reg_id", hex.EncodeToString(payload.GetSharedSecret()))

	clientAddr := parseIP(requestIP)
	var clientAddrBytes = make([]byte, 16)
	if clientAddr != nil {
		clientAddrBytes = []byte(clientAddr.To16())
	}

	// Check server's client config -- add server's ClientConf if client is outdated
	serverClientConf := s.compareClientConfGen(payload.GetRegistrationPayload().GetDecoyListGeneration())
	if serverClientConf != nil {
		// Replace the payload generation with correct generation from server's client config
		payload.RegistrationPayload.DecoyListGeneration = serverClientConf.Generation
	}

	// Create registration response object
	regResp, err := s.processor.RegisterBidirectional(payload, pb.RegistrationSource_BidirectionalAPI, clientAddrBytes)

	if err != nil {
		switch err {
		case regprocessor.ErrNoC2SBody:
			http.Error(w, "no C2S body", http.StatusBadRequest)
		default:
			w.WriteHeader(http.StatusInternalServerError)
		}
		return
	}

	if serverClientConf != nil {
		// Save the client config from server to return to client
		regResp.ClientConf = serverClientConf
	}

	// Add header to w (server response)
	w.WriteHeader(http.StatusOK)
	// Marshal (serialize) registration response object and then write it to w
	body, err := proto.Marshal(regResp)
	if err != nil {
		reqLogger.Errorf("failed to write registration into response: %v", err)
		return
	}

	_, err = w.Write(body)
	if err != nil {
		reqLogger.Errorf("failed to write registration into response: %v", err)
		return
	}

	reqLogger.Debugf("registration successful")

} // registerBidirectional()

// Use this function in registerBidirectional, if the returned ClientConfig is
// not nil add it to the RegistrationResponse.
func (s *APIRegServer) compareClientConfGen(genNum uint32) *pb.ClientConf {
	s.ccMutex.RLock()
	defer s.ccMutex.RUnlock()

	// Check that server has a currnet (latest) client config
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

// parseIP attempts to parse the IP address of a request from string format wether
// it has a port attached to it or not. Returns nil if parse fails.
func parseIP(addrPort string) *net.IP {

	// by default format from r.RemoteAddr is host:port
	host, _, err := net.SplitHostPort(addrPort)
	if err != nil || host == "" {
		// if the request ends up as host only this should catch it.
		addr := net.ParseIP(addrPort)
		if addr == nil {
			return nil
		}
		return &addr
	}

	addr := net.ParseIP(host)

	return &addr

}

func (s *APIRegServer) NewClientConf(c *pb.ClientConf) {
	if c != nil {
		s.ccMutex.Lock()
		defer s.ccMutex.Unlock()
		s.latestClientConf = c
	}
}

func (s *APIRegServer) ListenAndServe() error {
	r := mux.NewRouter()
	r.HandleFunc("/register", s.register)
	r.HandleFunc("/register-bidirectional", s.registerBidirectional)
	http.Handle("/", r)

	err := http.ListenAndServe(fmt.Sprintf(":%d", s.apiPort), nil)

	return err
}

func NewAPIRegServer(apiPort uint16, regprocessor *regprocessor.RegProcessor, latestCC *pb.ClientConf, logger log.FieldLogger, logClientIP bool, metrics *metrics.Metrics) (*APIRegServer, error) {
	if regprocessor == nil || latestCC == nil || logger == nil {
		return nil, errors.New("arguments cannot be nil")
	}
	return &APIRegServer{
		apiPort:          apiPort,
		processor:        regprocessor,
		latestClientConf: latestCC,
		ccMutex:          sync.RWMutex{},
		logger:           logger,
		logClientIP:      logClientIP,
		metrics:          metrics,
	}, nil
}
