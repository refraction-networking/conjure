module github.com/refraction-networking/conjure

go 1.18

// replace gitlab.com/yawning/obfs4.git => github.com/jmwample/obfs4.git v0.0.0-20230113193642-07b111e6b208

replace gitlab.com/yawning/obfs4.git => github.com/jmwample/obfs4 v0.0.0-20230113193642-07b111e6b208

require (
	git.torproject.org/pluggable-transports/goptlib.git v1.3.0
	github.com/BurntSushi/toml v1.2.1
	github.com/go-redis/redis/v8 v8.11.5
	github.com/gorilla/mux v1.8.0
	github.com/hashicorp/golang-lru v0.6.0
	github.com/mroth/weightedrand v1.0.0
	github.com/pebbe/zmq4 v1.2.9
	github.com/pelletier/go-toml v1.9.5
	github.com/refraction-networking/gotapdance v1.3.4
	github.com/sirupsen/logrus v1.9.0
	github.com/stretchr/testify v1.8.1
	gitlab.com/yawning/obfs4.git v0.0.0-20220204003609-77af0cba934d
	golang.org/x/crypto v0.5.0
	google.golang.org/grpc v1.52.0
	google.golang.org/protobuf v1.28.1
)

require (
	filippo.io/edwards25519 v1.0.0-rc.1.0.20210721174708-390f27c3be20 // indirect
	github.com/cespare/xxhash/v2 v2.1.2 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/dchest/siphash v1.2.1 // indirect
	github.com/dgryski/go-rendezvous v0.0.0-20200823014737-9f7001d12a5f // indirect
	github.com/flynn/noise v1.0.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	gitlab.com/yawning/edwards25519-extra.git v0.0.0-20211229043746-2f91fcc9fbdb // indirect
	golang.org/x/sys v0.4.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
