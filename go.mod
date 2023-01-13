module github.com/refraction-networking/conjure

go 1.16

require (
	filippo.io/edwards25519 v1.0.0 // indirect
	git.torproject.org/pluggable-transports/goptlib.git v1.2.0
	github.com/BurntSushi/toml v0.4.1
	github.com/dchest/siphash v1.2.3 // indirect
	github.com/go-redis/redis/v8 v8.11.4
	github.com/gorilla/mux v1.8.0
	github.com/hashicorp/golang-lru v0.5.4
	github.com/mroth/weightedrand v0.4.1
	github.com/pebbe/zmq4 v1.2.7
	github.com/pelletier/go-toml v1.9.4
	github.com/refraction-networking/gotapdance v1.3.1
	github.com/sirupsen/logrus v1.9.0
	github.com/stretchr/testify v1.7.1
	gitlab.com/yawning/obfs4.git v0.0.0-20220204003609-77af0cba934d
	golang.org/x/crypto v0.0.0-20220622213112-05595931fe9d
	google.golang.org/grpc v1.41.0
	google.golang.org/protobuf v1.28.0
)

// replace gitlab.com/yawning/obfs4.git => github.com/jmwample/obfs4.git v0.0.0-20230113193642-07b111e6b208

replace gitlab.com/yawning/obfs4.git => github.com/jmwample/obfs4 v0.0.0-20230113193642-07b111e6b208
