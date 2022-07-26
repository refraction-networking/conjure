package main

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/BurntSushi/toml"
	"github.com/gorilla/mux"
	zmq "github.com/pebbe/zmq4"
	lib "github.com/refraction-networking/conjure/application/lib"
	"github.com/refraction-networking/conjure/pkg/regprocessor"
	pb "github.com/refraction-networking/gotapdance/protobuf"
	"google.golang.org/protobuf/proto"
)

const (
	// The length of the shared secret sent by the client in bytes.
	regIDLen = 16

	// SecretLength gives the length of a secret (used for minimum registration body len)
	SecretLength = 32
)

type config struct {
	APIPort             uint16   `toml:"api_port"`
	ZMQPort             uint16   `toml:"zmq_port"`
	ZMQBindAddr         string   `toml:"zmq_bind_addr"`
	PrivateKeyPath      string   `toml:"privkey_path"`
	AuthType            string   `toml:"auth_type"`
	AuthVerbose         bool     `toml:"auth_verbose"`
	StationPublicKeys   []string `toml:"station_pubkeys"`
	BidirectionalAPIGen uint32   `toml:"bidirectional_api_generation"`
	ClientConfPath      string   `toml:"clientconf_path"`

	// Parsed from conjure.conf environment vars
	logClientIP bool
}

type APIRegServer struct {
	sync.Mutex
	config
	IPSelector *lib.PhantomIPSelector

	// Function to accept message into processing queue.
	// Abstracted to allow mocking of ZMQ send flow
	messageAccepter func([]byte) error

	logger *log.Logger
	sock   *zmq.Socket

	// Latest clientConf for sharing over RegistrationResponse channel.
	latestClientConf *pb.ClientConf

	processor *regprocessor.RegProcessor
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
	const MinimumRequestLength = SecretLength + 1 // shared_secret + VSP
	if r.Method != "POST" {
		s.logger.Printf("rejecting request due to incorrect method %s\n", r.Method)
		w.WriteHeader(http.StatusMethodNotAllowed)
		return nil, errors.New("incorrect method")
	}

	if r.ContentLength < MinimumRequestLength {
		s.logger.Printf("rejecting request due to short content-length of %d, expecting at least %d\n", r.ContentLength, MinimumRequestLength)
		http.Error(w, "Payload too small", http.StatusBadRequest)
		return nil, errors.New("payload too small")
	}

	in, err := ioutil.ReadAll(r.Body)
	if err != nil {
		s.logger.Println("failed to read request body:", err)
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return nil, errors.New("failed to read request body")
	}

	payload := &pb.C2SWrapper{}
	if err = proto.Unmarshal(in, payload); err != nil {
		s.logger.Println("failed to decode protobuf body:", err)
		http.Error(w, "Failed to decode protobuf body", http.StatusBadRequest)
		return nil, errors.New("failed to decode protobuf body")
	}

	return payload, nil
}

func (s *APIRegServer) register(w http.ResponseWriter, r *http.Request) {
	requestIP := getRemoteAddr(r)

	if s.logClientIP {
		s.logger.Printf("received %s request from IP %v with content-length %d\n", r.Method, requestIP, r.ContentLength)
	} else {
		s.logger.Printf("received %s request from IP _ with content-length %d\n", r.Method, r.ContentLength)
	}

	payload, err := s.getC2SFromReq(w, r)
	if err != nil {
		return
	}

	clientAddr := parseIP(requestIP)
	var clientAddrBytes = make([]byte, 16)
	if clientAddr != nil {
		clientAddrBytes = []byte(clientAddr.To16())
	}

	s.processor.RegisterUnidirectional(payload, clientAddrBytes, pb.RegistrationSource_API)

	// We could send an HTTP response earlier to avoid waiting
	// while the zmq socket is locked, but this ensures that
	// a 204 truly indicates registration success.
	w.WriteHeader(http.StatusNoContent)
}

func (s *APIRegServer) registerBidirectional(w http.ResponseWriter, r *http.Request) {
	requestIP := getRemoteAddr(r)

	if s.logClientIP {
		s.logger.Printf("received %s request from IP %v with content-length %d\n", r.Method, requestIP, r.ContentLength)
	} else {
		s.logger.Printf("received %s request from IP _ with content-length %d\n", r.Method, r.ContentLength)
	}

	payload, err := s.getC2SFromReq(w, r)
	if err != nil {
		return
	}

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
		s.logger.Println("failed to write registration into response:", err)
		return
	}

	_, err = w.Write(body)
	if err != nil {
		s.logger.Println("failed to write registration into response:", err)
		return
	}
} // registerBidirectional()

func (s *APIRegServer) sendToZMQ(message []byte) error {
	s.Lock()
	_, err := s.sock.SendBytes(message, zmq.DONTWAIT)
	s.Unlock()

	return err
}

// Function to parse the latest ClientConf based on path file
func parseClientConf(path string) (*pb.ClientConf, error) {
	// Create empty client config protobuf to return in case of error
	emptyPayload := &pb.ClientConf{}

	// Check that the filepath passed in exists
	if _, err := os.Stat(path); err != nil {
		fmt.Println("filepath does not exist:", path)
		return emptyPayload, err
	}

	// Open file path that stores the client config
	in, err := ioutil.ReadFile(path)
	if err != nil {
		fmt.Println("failed to read client config filepath:", err)
		return emptyPayload, err
	}

	// Create protobuf struct
	payload := &pb.ClientConf{}

	// Unmarshal into protobuf struct
	if err = proto.Unmarshal(in, payload); err != nil {
		fmt.Println("failed to decode protobuf body:", err)
		return emptyPayload, err
	}

	// If no error, return the payload (clientConf pb)
	return payload, nil
}

// Use this function in registerBidirectional, if the returned ClientConfig is
// not nil add it to the RegistrationResponse.
func (s *APIRegServer) compareClientConfGen(genNum uint32) *pb.ClientConf {
	// Check that server has a currnet (latest) client config
	if s.latestClientConf == nil {
		// s.logger.Println("Server latest ClientConf is nil")
		return nil
	}

	// s.logger.Printf("client: %d, stored: %d\n", genNum, s.latestClientConf.GetGeneration())
	// Check if generation number param is greater than server's client config
	if genNum >= s.latestClientConf.GetGeneration() {
		return nil
	}

	// Otherwise, return server's client config
	return s.latestClientConf
}

func (s *APIRegServer) processC2SWrapper(clientToAPIProto *pb.C2SWrapper, clientAddr []byte) ([]byte, error) {
	payload := &pb.C2SWrapper{}

	if clientToAPIProto == nil {
		return nil, fmt.Errorf("unable to process nil C2SWrapper")
	}

	if len(clientToAPIProto.GetSharedSecret()) < regIDLen/2 {
		return nil, fmt.Errorf("shared secret undefined or insufficient length")
	}

	// If the channel that the registration was received over was not specified
	// in the C2SWrapper set it here as API.
	if clientToAPIProto.GetRegistrationSource() == pb.RegistrationSource_Unspecified {
		source := pb.RegistrationSource_API
		payload.RegistrationSource = &source
	} else {
		source := clientToAPIProto.GetRegistrationSource()
		payload.RegistrationSource = &source
	}

	// If the address that the registration was received from was NOT set in the
	// C2SWrapper set it here to the source address of the API (uni or bidirectional) request.
	if clientToAPIProto.GetRegistrationAddress() == nil ||
		clientToAPIProto.GetRegistrationSource() == pb.RegistrationSource_API ||
		clientToAPIProto.GetRegistrationSource() == pb.RegistrationSource_BidirectionalAPI {
		payload.RegistrationAddress = clientAddr
	} else {
		payload.RegistrationAddress = clientToAPIProto.GetRegistrationAddress()
	}

	payload.SharedSecret = clientToAPIProto.GetSharedSecret()
	payload.RegistrationPayload = clientToAPIProto.GetRegistrationPayload()

	s.logger.Printf("forwarding registration %s source %v \n", hex.EncodeToString(payload.GetSharedSecret())[:regIDLen], payload.GetRegistrationSource())
	return proto.Marshal(payload)
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

func (s *APIRegServer) initPhantomSelector() {
	phantomSelector, err := lib.GetPhantomSubnetSelector()
	if err != nil {
		s.logger.Fatalln("failed to create phantom selector:", err)
	}

	s.IPSelector = phantomSelector
}

func (s *APIRegServer) ListenAndServe() error {
	r := mux.NewRouter()
	r.HandleFunc("/register", s.register)
	r.HandleFunc("/register-bidirectional", s.registerBidirectional)
	http.Handle("/", r)

	err := http.ListenAndServe(fmt.Sprintf(":%d", s.APIPort), nil)

	return err
}

func main() {
	var s APIRegServer
	s.logger = log.New(os.Stdout, "[API] ", log.Ldate|log.Lmicroseconds)
	s.messageAccepter = s.sendToZMQ

	_, err := toml.DecodeFile(os.Getenv("CJ_API_CONFIG"), &s)
	if err != nil {
		s.logger.Fatalln("failed to load config:", err)
	}

	// Set latest client config based on saved file path
	cc, err := parseClientConf(s.ClientConfPath)
	if err != nil {
		s.logger.Printf("failed to parse the latest ClientConf based on path file: %v\n", err)
	} else {
		s.latestClientConf = cc
	}

	// Should we log client IP addresses
	s.logClientIP, err = strconv.ParseBool(os.Getenv("LOG_CLIENT_IP"))
	if err != nil {
		s.logger.Printf("failed parse client ip logging setting: %v\n", err)
		s.logClientIP = false
	}

	sock, err := zmq.NewSocket(zmq.PUB)
	if err != nil {
		s.logger.Fatalln("failed to create zmq socket:", err)
	}

	s.initPhantomSelector()

	if s.AuthType == "CURVE" {
		privkeyBytes, err := ioutil.ReadFile(s.PrivateKeyPath)
		if err != nil {
			s.logger.Fatalln("failed to get private key:", err)
		}

		privkey := zmq.Z85encode(string(privkeyBytes[:32]))

		zmq.AuthSetVerbose(s.AuthVerbose)
		err = zmq.AuthStart()
		if err != nil {
			s.logger.Fatalln("failed to start zmq auth:", err)
		}

		s.logger.Println(s.StationPublicKeys)
		zmq.AuthAllow("*")
		zmq.AuthCurveAdd("*", s.StationPublicKeys...)

		err = sock.ServerAuthCurve("*", privkey)
		if err != nil {
			s.logger.Fatalln("failed to set up auth on zmq socket:", err)
		}
	}

	err = sock.Bind(fmt.Sprintf("tcp://%s:%d", s.ZMQBindAddr, s.ZMQPort))
	if err != nil {
		s.logger.Fatalln("failed to bind zmq socket:", err)
	}
	s.sock = sock

	s.logger.Println("bound zmq socket")

	s.logger.Printf("starting HTTP API on port %d\n", s.APIPort)

	err = s.ListenAndServe()

	s.logger.Fatalf(err.Error())
}
