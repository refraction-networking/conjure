module github.com/refraction-networking/conjure

go 1.21

toolchain go1.22.1

require (
	filippo.io/keygen v0.0.0-20230306160926-5201437acf8e
	github.com/BurntSushi/toml v1.4.0
	github.com/flynn/noise v1.1.0
	github.com/go-redis/redis/v8 v8.11.5
	github.com/google/gopacket v1.1.19
	github.com/gorilla/mux v1.8.1
	github.com/hashicorp/golang-lru v1.0.2
	github.com/libp2p/go-reuseport v0.4.0
	github.com/mroth/weightedrand v1.0.0
	github.com/oschwald/geoip2-golang v1.11.0
	github.com/pebbe/zmq4 v1.2.11
	github.com/pelletier/go-toml v1.9.5
	github.com/pion/dtls/v2 v2.2.11
	github.com/pion/logging v0.2.2
	github.com/pion/sctp v1.8.16
	github.com/pion/stun v0.6.1
	github.com/pion/transport/v2 v2.2.5
	github.com/refraction-networking/ed25519 v0.1.2
	github.com/refraction-networking/gotapdance v1.7.10
	github.com/refraction-networking/obfs4 v0.1.2
	github.com/refraction-networking/utls v1.6.6
	github.com/sirupsen/logrus v1.9.3
	github.com/stretchr/testify v1.9.0
	gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/goptlib v1.5.0
	golang.org/x/crypto v0.24.0
	golang.org/x/net v0.26.0
	golang.org/x/sys v0.21.0
	google.golang.org/grpc v1.64.0
	google.golang.org/protobuf v1.34.2
)

require (
	filippo.io/bigmod v0.0.1 // indirect
	github.com/andybalholm/brotli v1.1.0 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/cloudflare/circl v1.3.9 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/dchest/siphash v1.2.3 // indirect
	github.com/dgryski/go-rendezvous v0.0.0-20200823014737-9f7001d12a5f // indirect
	github.com/gaukas/godicttls v0.0.4 // indirect
	github.com/klauspost/compress v1.17.9 // indirect
	github.com/onsi/gomega v1.27.6 // indirect
	github.com/oschwald/maxminddb-golang v1.13.0 // indirect
	github.com/pion/randutil v0.1.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/sergeyfrolov/bsbuffer v0.0.0-20180903213811-94e85abb8507 // indirect
	golang.org/x/text v0.16.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/pion/dtls/v2 => github.com/mingyech/dtls/v2 v2.0.0

replace github.com/pion/transport/v2 => github.com/mingyech/transport/v2 v2.0.0
