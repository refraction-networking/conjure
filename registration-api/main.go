package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"sync"

	"github.com/BurntSushi/toml"
	"github.com/golang/protobuf/proto"
	"github.com/gorilla/mux"
	zmq "github.com/pebbe/zmq4"
	pb "github.com/refraction-networking/gotapdance/protobuf"
)

const (
	// The length of the shared secret sent by the client in bytes.
	SecretLength = 32
)

type config struct {
	APIPort           uint16   `toml:"api_port"`
	ZMQPort           uint16   `toml:"zmq_port"`
	PrivateKeyPath    string   `toml:"privkey_path"`
	AuthType          string   `toml:"auth_type"`
	AuthVerbose       bool     `toml:"auth_verbose"`
	StationPublicKeys []string `toml:"station_pubkeys"`
}

type server struct {
	sync.Mutex
	config

	// Function to accept message into processing queue. Abstracted
	// to allow mocking of ZMQ send flow
	messageAccepter func([]byte) error

	logger *log.Logger
	sock   *zmq.Socket
}

func (s *server) register(w http.ResponseWriter, r *http.Request) {
	requestIP := r.RemoteAddr
	if r.Header.Get("X-Forwarded-For") != "" {
		requestIP = r.Header.Get("X-Forwarded-For")
	}

	s.logger.Printf("received %s request from IP %v with content-length %d\n", r.Method, requestIP, r.ContentLength)

	const MinimumRequestLength = SecretLength + 1 // shared_secret + VSP
	if r.Method != "POST" {
		s.logger.Printf("rejecting request due to incorrect method %s\n", r.Method)
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	if r.ContentLength < MinimumRequestLength {
		s.logger.Printf("rejecting request due to short content-length of %d, expecting at least %d\n", r.ContentLength, MinimumRequestLength)
		http.Error(w, "Payload too small", http.StatusBadRequest)
		return
	}

	in, err := ioutil.ReadAll(r.Body)
	if err != nil {
		s.logger.Println("failed to read request body:", err)
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}

	payload := &pb.C2SWrapper{}
	if err = proto.Unmarshal(in, payload); err != nil {
		s.logger.Println("failed to decode protobuf body:", err)
		http.Error(w, "Failed to decode protobuf body", http.StatusBadRequest)
		return
	}

	// s.logger.Printf("received successful registration for covert address %s\n", payload.RegistrationPayload.GetCovertAddress())

	clientAddr := parseIP(requestIP)
	if err != nil {
		s.logger.Println("failed to get source address:", err)
	}

	zmqPayload, err := processC2SWrapper(payload, []byte(clientAddr.To16()))
	if err != nil {
		s.logger.Println("failed to marshal ClientToStation into VSP:", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	err = s.messageAccepter(zmqPayload)
	if err != nil {
		s.logger.Println("failed to publish registration:", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// We could send an HTTP response earlier to avoid waiting
	// while the zmq socket is locked, but this ensures that
	// a 204 truly indicates registration success.
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) sendToZMQ(message []byte) error {
	s.Lock()
	_, err := s.sock.SendBytes(message, zmq.DONTWAIT)
	s.Unlock()

	return err
}

func processC2SWrapper(clientToAPIProto *pb.C2SWrapper, clientAddr []byte) ([]byte, error) {
	payload := &pb.C2SWrapper{}

	if clientToAPIProto == nil {
		return nil, fmt.Errorf("unable to process nil C2SWrapper")
	}

	// If the channel that the registration was received over was not specified
	// in the C2SWrapper set it here as API.
	if clientToAPIProto.RegistrationSource == nil {
		source := pb.RegistrationSource_API
		payload.RegistrationSource = &source
	} else {
		source := clientToAPIProto.GetRegistrationSource()
		payload.RegistrationSource = &source
	}

	// If the address that the registration was received from was NOT set in the
	// C2SWrapper set it here to the source address of the API request.
	if clientToAPIProto.RegistrationAddress == nil {
		payload.RegistrationAddress = clientAddr
	}

	payload.SharedSecret = clientToAPIProto.SharedSecret
	payload.RegistrationPayload = clientToAPIProto.RegistrationPayload

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

func main() {
	var s server
	s.logger = log.New(os.Stdout, "[API] ", log.Ldate|log.Lmicroseconds)
	s.messageAccepter = s.sendToZMQ

	_, err := toml.DecodeFile(os.Getenv("CJ_API_CONFIG"), &s)
	if err != nil {
		s.logger.Fatalln("failed to load config:", err)
	}

	sock, err := zmq.NewSocket(zmq.PUB)
	if err != nil {
		s.logger.Fatalln("failed to create zmq socket:", err)
	}

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

	err = sock.Bind(fmt.Sprintf("tcp://*:%d", s.ZMQPort))
	if err != nil {
		s.logger.Fatalln("failed to bind zmq socket:", err)
	}
	s.sock = sock

	s.logger.Println("bound zmq socket")

	s.logger.Printf("starting HTTP API on port %d\n", s.APIPort)

	r := mux.NewRouter()
	r.HandleFunc("/register", s.register)
	http.Handle("/", r)

	s.logger.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", s.APIPort), nil))
}
