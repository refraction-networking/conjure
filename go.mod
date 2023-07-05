module github.com/refraction-networking/conjure

go 1.18

// replace gitlab.com/yawning/obfs4.git => github.com/jmwample/obfs4.git v0.0.0-20230113193642-07b111e6b208

replace gitlab.com/yawning/obfs4.git => github.com/jmwample/obfs4 v0.0.0-20230113193642-07b111e6b208

require (
	git.torproject.org/pluggable-transports/goptlib.git v1.3.0
	github.com/BurntSushi/toml v1.2.1
	github.com/flynn/noise v1.0.0
	github.com/go-redis/redis/v8 v8.11.5
	github.com/gorilla/mux v1.8.0
	github.com/hashicorp/golang-lru v0.6.0
	github.com/mroth/weightedrand v1.0.0
	github.com/oschwald/geoip2-golang v1.8.0
	github.com/pebbe/zmq4 v1.2.9
	github.com/pelletier/go-toml v1.9.5
	github.com/pion/stun v0.3.5
	github.com/refraction-networking/gotapdance v1.5.5
	github.com/refraction-networking/utls v1.2.0
	github.com/sirupsen/logrus v1.9.0
	github.com/stretchr/testify v1.8.1
	gitlab.com/yawning/obfs4.git v0.0.0-20230519154740-645026c2ada4
	golang.org/x/crypto v0.9.0
	golang.org/x/net v0.10.0
	google.golang.org/grpc v1.53.0
	google.golang.org/protobuf v1.31.0
)

require (
	filippo.io/edwards25519 v1.0.0 // indirect
	github.com/andybalholm/brotli v1.0.4 // indirect
	github.com/cespare/xxhash/v2 v2.2.0 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/dchest/siphash v1.2.3 // indirect
	github.com/dgryski/go-rendezvous v0.0.0-20200823014737-9f7001d12a5f // indirect
	github.com/golang/protobuf v1.5.3 // indirect
	github.com/klauspost/compress v1.15.12 // indirect
	github.com/oschwald/maxminddb-golang v1.10.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/sergeyfrolov/bsbuffer v0.0.0-20180903213811-94e85abb8507 // indirect
	gitlab.com/yawning/edwards25519-extra.git v0.0.0-20220726154925-def713fd18e4 // indirect
	golang.org/x/sys v0.8.0 // indirect
	golang.org/x/text v0.9.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
