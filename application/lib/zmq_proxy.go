package lib

//

import (
	"fmt"
	golog "log"
	"os"
	"time"

	zmq "github.com/pebbe/zmq4"

	"github.com/refraction-networking/conjure/application/log"
)

// ZMQConfig - Configuration options relevant to the ZMQ Proxy utility
type ZMQConfig struct {
	SocketName        string         `toml:"socket_name"`
	ConnectSockets    []socketConfig `toml:"connect_sockets"`
	PrivateKeyPath    string         `toml:"privkey_path"`
	HeartbeatInterval int            `toml:"heartbeat_interval"`
	HeartbeatTimeout  int            `toml:"heartbeat_timeout"`
}

type socketConfig struct {
	Address            string `toml:"address"`
	AuthenticationType string `toml:"type"`
	PublicKey          string `toml:"pubkey"`
	SubscriptionPrefix string `toml:"subscription"`
}

type proxy struct {
	logger *log.Logger
}

// ZMQProxy - centralizing proxy used to channel multiple registration sources into
// one PUB socket for consumption by the application.
// Specify the absolute location of the config file with
// the CJ_PROXY_CONFIG environment variable.
func ZMQProxy(c ZMQConfig) {
	var p proxy
	p.logger = log.New(os.Stdout, "[ZMQ_PROXY] ", golog.Ldate|golog.Lmicroseconds)

	privkey, err := os.ReadFile(c.PrivateKeyPath)
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

	pubSock, err := zmq.NewSocket(zmq.PUB)
	if err != nil {
		p.logger.Fatalln("failed to create binding zmq socket:", err)
	}

	err = pubSock.Bind(fmt.Sprintf("ipc://@%s", c.SocketName))
	if err != nil {
		p.logger.Fatalln("failed to bind zmq socket:", err)
	}
	defer pubSock.Close()

	messages := make(chan []byte)
	// Create a socket for each socket we're connecting to. I would've
	// liked to use a single socket for all connections, and ZMQ actually
	// does support connecting to multiple sockets from a single socket,
	// but it appears that it doesn't support setting different auth
	// parameters for each connection.
	for _, connectSocket := range c.ConnectSockets {
		sock, err := zmq.NewSocket(zmq.SUB)
		if err != nil {
			p.logger.Errorf("failed to create subscriber zmq socket for %s: %v\n", connectSocket.Address, err)
		}

		err = sock.SetHeartbeatIvl(time.Duration(c.HeartbeatInterval) * time.Millisecond)
		if err != nil {
			p.logger.Errorf("failed to set heartbeat interval of %v for %s: %v\n", c.HeartbeatInterval, connectSocket.Address, err)
		}

		err = sock.SetHeartbeatTimeout(time.Duration(c.HeartbeatTimeout) * time.Millisecond)
		if err != nil {
			p.logger.Errorf("failed to set heartbeat timeout of %v for %s: %v\n", c.HeartbeatTimeout, connectSocket.Address, err)
		}

		if connectSocket.AuthenticationType == "CURVE" {
			err = sock.ClientAuthCurve(connectSocket.PublicKey, pubkey_z85, privkey_z85)
			if err != nil {
				p.logger.Errorf("failed to set up CURVE authentication for %s: %v\n", connectSocket.Address, err)
				continue
			}
		}

		err = sock.SetSubscribe(connectSocket.SubscriptionPrefix)
		if err != nil {
			p.logger.Errorf("failed to set subscription prefix for %s: %v\n", connectSocket.Address, err)
			continue
		}

		err = sock.Connect(connectSocket.Address)
		if err != nil {
			p.logger.Errorf("failed to connect to %s: %v\n", connectSocket.Address, err)
			continue
		}
		defer sock.Close()

		go func(sub *zmq.Socket, config socketConfig) {
			for {
				msg, err := sub.RecvBytes(0)
				if err != nil {
					p.logger.Errorf("read from %s failed: %v\n", config.Address, err)
					continue
				}
				messages <- msg
			}
		}(sock, connectSocket)
	}

	for msg := range messages {
		_, err := pubSock.SendBytes(msg, 0)
		if err != nil {
			p.logger.Errorf("write to pubSock failed: %v\n", err)
		}
	}
}

// RunZMQ start the receive loop that writes into the provided message receive channel
func RunZMQ(connectAddr string, regChan chan<- interface{}, conf *Config) {
	logger := log.New(os.Stdout, "[ZMQ] ", golog.Ldate|golog.Lmicroseconds)
	sub, err := zmq.NewSocket(zmq.SUB)
	if err != nil {
		logger.Errorf("could not create new ZMQ socket: %v\n", err)
		return
	}
	defer sub.Close()

	err = sub.Connect(connectAddr)
	if err != nil {
		logger.Errorln("error connecting to zmq publisher:", err)
	}
	err = sub.SetSubscribe("")
	if err != nil {
		logger.Errorln("error subscribing to zmq:", err)
	}

	logger.Infof("ZMQ connected to %v\n", connectAddr)

	for {

		msg, err := sub.RecvBytes(0)
		if err != nil {
			logger.Fatalf("error reading from ZMQ socket: %v\n", err)
		}
		select {
		case regChan <- msg:
			continue
		default:
			// drop reg, ingest is too busy to handle it.
			logger.Warnln("ingest full, dropping zmq message")
			//TODO JMWAMPLE STATS
			Stat().AddDroppedZMQMessage()
		}

	}
}
