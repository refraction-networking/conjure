package main

import (
	"flag"
	//"fmt"
	zmq "github.com/pebbe/zmq4"
	"log"
	"net"
	"os"

	//cj "github.com/refraction-networking/conjure/application/lib"
	pb "github.com/refraction-networking/gotapdance/protobuf"
	//"github.com/refraction-networking/gotapdance/tapdance/phantoms"
	"google.golang.org/protobuf/proto"
)

func main() {

	var zmqAddress string
	flag.StringVar(&zmqAddress, "zmq-address", "ipc://@zmq-proxy", "Address of ZMQ proxy")
	flag.Parse()

	logger := log.New(os.Stdout, "", log.Ldate|log.Lmicroseconds)

	sub, err := zmq.NewSocket(zmq.SUB)
	if err != nil {
		logger.Printf("could not create new ZMQ socket: %v\n", err)
		return
	}
	defer sub.Close()

	err = sub.Connect(zmqAddress)
	if err != nil {
		logger.Println("error connecting to zmq publisher:", err)
	}
	err = sub.SetSubscribe("")
	if err != nil {
		logger.Println("error subscribing to zmq:", err)
	}

	for {
		msg, err := sub.RecvBytes(0)
		if err != nil {
			logger.Printf("error reading from ZMQ socket: %v\n", err)
			return
		}

		parsed := &pb.C2SWrapper{}
		err = proto.Unmarshal(msg, parsed)
		if err != nil {
			logger.Printf("Failed to unmarshall ClientToStation: %v", err)
			return
		}

		// if either addres is not provided (reg came over api / client ip
		// logging disabled) fill with zeros to avoid nil dereference.
		if parsed.GetRegistrationAddress() == nil {
			parsed.RegistrationAddress = make([]byte, 16)
		}
		if parsed.GetDecoyAddress() == nil {
			parsed.DecoyAddress = make([]byte, 16)
		}

		// If client IP logging is disabled DO NOT parse source IP.
		var sourceAddr, phantomAddr net.IP
		sourceAddr = net.IP(parsed.GetRegistrationAddress())
		phantomAddr = net.IP(parsed.GetDecoyAddress())

		logger.Printf("%v %v\n", sourceAddr, phantomAddr)
	}
}
