package main

import (
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"sync"

	"github.com/golang/protobuf/proto"
	zmq "github.com/pebbe/zmq4"
	pb "github.com/refraction-networking/gotapdance/protobuf"
)

type server struct {
	sync.Mutex

	logger *log.Logger
	sock   *zmq.Socket
}

func (s *server) register(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	in, err := ioutil.ReadAll(r.Body)
	if err != nil {
		s.logger.Println("failed to read request body:", err)
		http.Error(w, "Failed to read request body", http.StatusBadRequest)
		return
	}

	payload := &pb.ClientToStation{}
	if err := proto.Unmarshal(in, payload); err != nil {
		s.logger.Println("failed to decode protobuf body:", err)
		http.Error(w, "Failed to decode protobuf body", http.StatusBadRequest)
		return
	}

	s.logger.Printf("received successful registration for covert address %s\n", payload.GetCovertAddress())

	s.Lock()
	_, err = s.sock.SendBytes(in, zmq.DONTWAIT)
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

	sock, err := zmq.NewSocket(zmq.PUB)
	if err != nil {
		log.Fatalf("failed to create zmq socket: %v\n", err)
	}

	// TODO: add more robust zmq handling (auth)
	err = sock.Bind("tcp://*:5591")
	if err != nil {
		log.Fatalf("failed to bind zmq socket: %v\n", err)
	}
	s.sock = sock

	s.logger.Println("bound zmq socket")

	// TODO: possibly use router with more complex features?
	// For now net/http does the job
	http.HandleFunc("/register", s.register)
	s.logger.Fatal(http.ListenAndServe(":8080", nil))
}
