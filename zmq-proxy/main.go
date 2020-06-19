// Proxy used to channel multiple registration sources into
// one PUB socket for consumption by the application.
// Specify the absolute location of the config file with
// the CJ_PROXY_CONFIG environment variable.

package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/BurntSushi/toml"
	zmq "github.com/pebbe/zmq4"
)

type config struct {
	Port           uint16         `toml:"port"`
	Servers        []serverConfig `toml:"servers"`
	PrivateKeyPath string         `toml:"privkey_path"`
}

type serverConfig struct {
	Address            string `toml:"address"`
	AuthenticationType string `toml:"type"`
	PublicKey          string `toml:"pubkey"`
	SubscriptionPrefix string `toml:"subscription"`
}

type proxy struct {
	logger *log.Logger

	pubSocket *zmq.Socket
	pubChan   chan ([]byte)
}

func (p *proxy) pubChanMessages() {
	for m := range p.pubChan {
		_, err := p.pubSocket.SendBytes(m, zmq.DONTWAIT)
		if err != nil {
			p.logger.Println("failed to publish message to channel:", err)
		}
	}
}

func main() {
	var p proxy
	p.logger = log.New(os.Stdout, "[ZMQ_PROXY] ", log.Ldate|log.Lmicroseconds)
	configFile, err := ioutil.ReadFile(os.Getenv("CJ_PROXY_CONFIG"))
	if err != nil {
		p.logger.Fatalln("failed to open config file:", err)
	}

	var c config
	err = toml.Unmarshal(configFile, &c)
	if err != nil {
		p.logger.Fatalln("failed to parse config file:", err)
	}

	privkey, err := ioutil.ReadFile(c.PrivateKeyPath)
	if err != nil {
		p.logger.Fatalln("failed to load private key:", err)
	}

	// Only use first 32 bytes of key (some keys store
	// public key after private key)
	privkey_z85 := zmq.Z85encode(string(privkey[:32]))
	pubkey_z85, err := zmq.AuthCurvePublic(privkey_z85)
	if err != nil {
		p.logger.Fatalln("failed to generate client public key from private key:", err)
	}

	bindSock, err := zmq.NewSocket(zmq.PUB)
	if err != nil {
		p.logger.Fatalln("failed to create binding zmq socket:", err)
	}

	err = bindSock.Bind(fmt.Sprintf("tcp://*:%d", c.Port))
	if err != nil {
		p.logger.Fatalln("failed to bind zmq socket:", err)
	}

	p.pubSocket = bindSock
	p.pubChan = make(chan []byte)

	for _, server := range c.Servers {
		connectSock, err := zmq.NewSocket(zmq.SUB)
		if err != nil {
			p.logger.Printf("failed to create connecting zmq socket for %s: %v\n", server.Address, err)
			continue
		}

		if server.AuthenticationType == "CURVE" {
			err = connectSock.ClientAuthCurve(server.PublicKey, pubkey_z85, privkey_z85)
			if err != nil {
				p.logger.Printf("failed to set up CURVE authentication for %s: %v\n", server.Address, err)
				continue
			}
		}

		err = connectSock.SetSubscribe(server.SubscriptionPrefix)
		if err != nil {
			p.logger.Printf("failed to set subscription prefix for %s: %v\n", server.Address, err)
			continue
		}

		err = connectSock.Connect(server.Address)
		if err != nil {
			p.logger.Printf("failed to connect to %s: %v\n", server.Address, err)
			continue
		}

		go func(sock *zmq.Socket, s serverConfig, toPub chan<- ([]byte)) {
			for {
				m, err := sock.RecvBytes(0)
				if err != nil {
					p.logger.Printf("failed to read message on %s: %v\n", s.Address, err)
					return
				}

				p.logger.Println("received message from", s.Address)
				toPub <- m
			}
		}(connectSock, server, p.pubChan)
	}

	p.pubChanMessages()
}
