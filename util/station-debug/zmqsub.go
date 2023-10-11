package main

import (
	"flag"
	//"fmt"
	zmq "github.com/pebbe/zmq4"
	golog "log"
	"net"
	"os"
	"strconv"

	// "github.com/refraction-networking/conjure/pkg/dtls/dnat"
	// "github.com/refraction-networking/conjure/pkg/transports/connecting/dtls"
	"github.com/refraction-networking/conjure/pkg/station/log"
	cj "github.com/refraction-networking/conjure/pkg/station/lib"
	"github.com/refraction-networking/conjure/pkg/transports/wrapping/min"
	"github.com/refraction-networking/conjure/pkg/transports/wrapping/obfs4"
	"github.com/refraction-networking/conjure/pkg/transports/wrapping/prefix"
	pb "github.com/refraction-networking/conjure/proto"

	"google.golang.org/protobuf/proto"
)

var enabledTransports = map[pb.TransportType]cj.Transport{
	pb.TransportType_Min:    min.Transport{},
	pb.TransportType_Obfs4:  obfs4.Transport{},
	pb.TransportType_Prefix: prefix.Transport{},
}

func handleReg(logger *log.Logger, source net.IP, reg *cj.DecoyRegistration) {

	logger.Printf("%v %v:%v %+v\n", source, reg.PhantomProto, net.JoinHostPort(reg.PhantomIp.String(), strconv.FormatUint(uint64(reg.PhantomPort), 10)), reg)
}

func main() {

	var zmqAddress string
	flag.StringVar(&zmqAddress, "zmq-address", "ipc://@zmq-proxy", "Address of ZMQ proxy")
	flag.Parse()

	logger := log.New(os.Stdout, "", golog.Ldate|golog.Lmicroseconds)

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

	regManager := cj.NewRegistrationManager(&cj.RegConfig{})

	// dtlsbuilder := dnat.NewDNAT
	// dtlsTransport, err := dtls.NewTransport(nil, nil, nil, nil, dtlsbuilder)
	// if err != nil {
	// 	log.Fatalf("failed to setup dtls: %v", err)
	// }
	// enabledTransports[pb.TransportType_DTLS] = dtlsTransport

	// Add supported transport options for registration validation
	for transportType, transport := range enabledTransports {
		err = regManager.AddTransport(transportType, transport)
		if err != nil {
			logger.Errorf("failed to add transport: %v", err)
		}
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
		var sourceAddr net.IP
		sourceAddr = net.IP(parsed.GetRegistrationAddress())

		if parsed.GetRegistrationPayload().GetV4Support() && sourceAddr.To4() != nil {
			reg, err := regManager.NewRegistrationC2SWrapper(parsed, false)
			if err != nil {
				logger.Printf("Failed to create registration: %v", err)
				return
			}
			handleReg(logger, sourceAddr, reg)
		}


	        if parsed.GetRegistrationPayload().GetV6Support() {
		    reg, err := regManager.NewRegistrationC2SWrapper(parsed, true)
		    if err != nil {
		        logger.Printf("Failed to create registration: %v", err)
			return
		    }
		    handleReg(logger, sourceAddr, reg)
		}

	}
}
