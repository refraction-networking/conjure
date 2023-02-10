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
	"github.com/refraction-networking/conjure/application/lib"
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

var clientIPHeaderNames = []string{
	"X-Forwarded-For",
	// "X-Client-IP",
	// "True-Client-IP",
}

// getRemoteAddr gets the last entry of the last instance of the X-Forwarded-For
// header if it is available, this is our best guess at the clients address if
// intermediate proxies follow X-Forwarded-For specification (as seen here:
// https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Forwarded-For).
// Otherwise return the remote address specified in the request.
//
// In the future this may need to handle True-Client-IP headers, but in general
// none of these are to be trusted -
// https://adam-p.ca/blog/2022/03/x-forwarded-for/. If those are enabled in
// clientIPHeaderNames ensure that the ordering checks them in order of most to
// least trusted.
func getRemoteAddr(r *http.Request) net.IP {

	// Default to the clients remote address if no identifying header is provided
	ip := parseIP(r.RemoteAddr)

	// When there are multiple header names in clientIPHeaderNames,
	// the first valid match is preferred. clientIPHeaderNames should be
	// configured to use header names that are always provided by the CDN(s) and
	// not header names that may be passed through from clients.
	for _, header := range clientIPHeaderNames {

		// In the case where there are multiple headers,
		// request.Header.Get returns the first header, but we want the
		// last header; so use request.Header.Values and select the last
		// value. As per RFC 2616 section 4.2, a proxy must not change
		// the order of field values, which implies that it should append
		// values to the last header.
		values := r.Header.Values(header)
		if len(values) > 0 {
			value := values[len(values)-1]

			// Some headers, such as X-Forwarded-For, are a comma-separated
			// list of IPs (each proxy in a chain). Select the last IP.
			IPs := strings.Split(value, ",")
			IP := IPs[len(IPs)-1]

			// Caddy appends an X-Forward-For from the client (potentially CDN)
			// We configure Caddy to trust the domain-fronted proxies,
			// which will give us a list of real_client_ip, cdn_ip.
			// In that case, r.RemoteAddr will be localhost, and we want
			// to skip the CDN IP in the list
			if len(IPs) > 1 &&
				(ip.Equal(net.ParseIP("127.0.0.1")) ||
					ip.Equal(net.ParseIP("::1"))) {
				IP = IPs[len(IPs)-2]
			}

			// Remove optional whitespace surrounding the commas.
			IP = strings.TrimSpace(IP)

			headerIP := net.ParseIP(IP)
			if headerIP != nil {
				ip = headerIP
				break
			}
		}
	}

	return ip
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

	clientAddr := getRemoteAddr(r)
	if clientAddr == nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	logFields := log.Fields{"http_method": r.Method, "content_length": r.ContentLength, "registration_type": "unidirectional"}
	if s.logClientIP {
		logFields["ip_address"] = clientAddr.String()
	}
	reqLogger := s.logger.WithFields(logFields)

	reqLogger.Debugf("recived new request")

	payload, err := s.getC2SFromReq(w, r)
	if err != nil {
		reqLogger.Errorf("registration failed: %v", err)
		return
	}

	reqLogger = reqLogger.WithField("reg_id", hex.EncodeToString(payload.GetSharedSecret()))

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

	clientAddr := getRemoteAddr(r)
	if clientAddr == nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	logFields := log.Fields{"http_method": r.Method, "content_length": r.ContentLength, "registration_type": "bidirectional"}
	if s.logClientIP {
		logFields["ip_address"] = clientAddr.String()
	}
	reqLogger := s.logger.WithFields(logFields)

	reqLogger.Debugf("received new request")

	payload, err := s.getC2SFromReq(w, r)
	if err != nil {
		return
	}

	reqLogger = reqLogger.WithField("reg_id", hex.EncodeToString(payload.GetSharedSecret()))

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
		case lib.ErrLegacyAddrSelectBug:
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

// parseIP attempts to parse the IP address of a request from string format wether
// it has a port attached to it or not. Returns nil if parse fails.
func parseIP(addrPort string) net.IP {

	// by default format from r.RemoteAddr is host:port
	host, _, err := net.SplitHostPort(addrPort)
	if err != nil || host == "" {
		// if the request ends up as host only this should catch it.
		addr := net.ParseIP(addrPort)
		if addr == nil {
			return nil
		}
		return addr
	}

	addr := net.ParseIP(host)

	return addr
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
