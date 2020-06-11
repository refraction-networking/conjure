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

	spec := &pb.ClientToStation{}
	if err := proto.Unmarshal(in, spec); err != nil {
		s.logger.Println("failed to decode protobuf body:", err)
		http.Error(w, "Failed to decode protobuf body", http.StatusBadRequest)
		return
	}
	w.WriteHeader(http.StatusNoContent)

	s.logger.Println("received successful HTTP request")

	s.Lock()
	_, err = s.sock.SendBytes(in, zmq.DONTWAIT)
	s.Unlock()

	if err != nil {
		s.logger.Println("failed to send registration info to zmq socket:", err)
	}
}

func main() {
	var serv server
	serv.logger = log.New(os.Stdout, "[API] ", log.Ldate|log.Lmicroseconds)

	sock, err := zmq.NewSocket(zmq.PUB)
	if err != nil {
		log.Fatalf("failed to create zmq socket: %v\n", err)
	}

	// TODO: the fact that this is a connection rather than a bind
	// is due to how the application and detector relationship is
	// set up; we should form a more robust zmq architecture
	// that allows both multiple publishers and multiple subscribers
	err = sock.Connect("tcp://127.0.0.1:5591")
	if err != nil {
		log.Fatalf("failed to connect to zmq socket: %v\n", err)
	}
	serv.sock = sock

	serv.logger.Println("connected to zmq socket")

	// TODO: possibly use router with more complex features?
	// For now net/http does the job
	http.HandleFunc("/register", serv.register)
	serv.logger.Fatal(http.ListenAndServe(":8080", nil))
}
