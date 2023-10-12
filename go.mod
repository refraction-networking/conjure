module github.com/refraction-networking/conjure

go 1.18

require (
	github.com/BurntSushi/toml v1.3.2
	github.com/flynn/noise v1.0.0
	github.com/go-redis/redis/v8 v8.11.5
	github.com/google/gopacket v1.1.19
	github.com/gorilla/mux v1.8.0
	github.com/hashicorp/golang-lru v1.0.2
	github.com/libp2p/go-reuseport v0.4.0
	github.com/mroth/weightedrand v1.0.0
	github.com/oschwald/geoip2-golang v1.9.0
	github.com/pebbe/zmq4 v1.2.10
	github.com/pelletier/go-toml v1.9.5
	github.com/pion/dtls/v2 v2.2.7
	github.com/pion/logging v0.2.2
	github.com/pion/sctp v1.8.8
	github.com/pion/stun v0.6.1
	github.com/pion/transport/v2 v2.2.3
	github.com/refraction-networking/ed25519 v0.1.2
	github.com/refraction-networking/gotapdance v1.7.5-0.20231008035356-980b28fc1555
	github.com/refraction-networking/obfs4 v0.1.2
	github.com/refraction-networking/utls v1.3.3
	github.com/sirupsen/logrus v1.9.3
	github.com/stretchr/testify v1.8.4
	gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/goptlib v1.5.0
	golang.org/x/crypto v0.14.0
	golang.org/x/net v0.17.0
	golang.org/x/sys v0.13.0
	google.golang.org/grpc v1.58.0
	google.golang.org/protobuf v1.31.0
)

require (
	github.com/andybalholm/brotli v1.0.5 // indirect
	github.com/cespare/xxhash/v2 v2.2.0 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/dchest/siphash v1.2.3 // indirect
	github.com/dgryski/go-rendezvous v0.0.0-20200823014737-9f7001d12a5f // indirect
	github.com/gaukas/godicttls v0.0.4 // indirect
	github.com/klauspost/compress v1.16.7 // indirect
	github.com/onsi/gomega v1.27.6 // indirect
	github.com/oschwald/maxminddb-golang v1.12.0 // indirect
	github.com/pion/randutil v0.1.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/sergeyfrolov/bsbuffer v0.0.0-20180903213811-94e85abb8507 // indirect
	golang.org/x/text v0.13.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/pion/dtls/v2 => github.com/mingyech/dtls/v2 v2.0.0

replace github.com/pion/transport/v2 => github.com/mingyech/transport/v2 v2.0.0
