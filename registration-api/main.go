package main

import (
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"sync"

	"github.com/BurntSushi/toml"
	"github.com/golang/protobuf/proto"
	zmq "github.com/pebbe/zmq4"
	pb "github.com/refraction-networking/gotapdance/protobuf"
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

	logger *log.Logger
	sock   *zmq.Socket
}

func (s *server) register(w http.ResponseWriter, r *http.Request) {
	const MINIMUM_REQUEST_LENGTH = 32 + 1 // shared_secret + VSP
	if r.Method != "POST" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	if r.ContentLength < MINIMUM_REQUEST_LENGTH {
		http.Error(w, "Payload too small", http.StatusBadRequest)
		return
	}

	in, err := ioutil.ReadAll(r.Body)
	if err != nil {
		s.logger.Println("failed to read request body:", err)
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}

	payload := &pb.ClientToAPI{}
	if err = proto.Unmarshal(in, payload); err != nil {
		s.logger.Println("failed to decode protobuf body:", err)
		http.Error(w, "Failed to decode protobuf body", http.StatusBadRequest)
		return
	}

	s.logger.Printf("received successful registration for covert address %s\n", payload.RegistrationPayload.GetCovertAddress())

	// Marshal the ClientToStation message from the request body. Although
	// it was already sent as marshaled in the body, this keeps us from
	// relying on the specific position in the generated protobuf.
	// We also need its size to generate the FSP for the application.
	vsp, err := proto.Marshal(payload.RegistrationPayload)
	if err != nil {
		s.logger.Println("failed to marshal CleintToStation into VSP:", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// Adding 16 to simulate the presence of the AEC-GCM tag. The application
	// subtracts this value before parsing the VSP.
	vspSize := uint16(len(vsp) + 16)
	fsp := make([]byte, 6)
	binary.BigEndian.PutUint16(fsp[:2], vspSize)

	zmqPayload := payload.GetSecret()
	zmqPayload = append(zmqPayload, fsp...)
	zmqPayload = append(zmqPayload, vsp...)

	s.Lock()
	_, err = s.sock.SendBytes(zmqPayload, zmq.DONTWAIT)
	s.Unlock()

	if err != nil {
		s.logger.Println("failed to send registration info to zmq socket:", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	// We could send an HTTP response earlier to avoid waiting
	// while the zmq socket is locked, but this ensures that
	// a 204 truly indicates registration success.
	w.WriteHeader(http.StatusNoContent)
}

func main() {
	var s server
	s.logger = log.New(os.Stdout, "[API] ", log.Ldate|log.Lmicroseconds)

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

	// TODO: possibly use router with more complex features?
	// For now net/http does the job
	http.HandleFunc("/register", s.register)
	s.logger.Fatal(http.ListenAndServe(fmt.Sprintf(":%d", s.APIPort), nil))
}
