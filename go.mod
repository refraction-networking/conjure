module github.com/refraction-networking/conjure

go 1.22

toolchain go1.22.5

require (
	filippo.io/keygen v0.0.0-20230306160926-5201437acf8e
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
	github.com/pion/sctp v1.8.9
	github.com/pion/stun v0.6.1
	github.com/pion/transport/v2 v2.2.3
	github.com/refraction-networking/ed25519 v0.1.2
	github.com/refraction-networking/gotapdance v1.7.7
	github.com/refraction-networking/obfs4 v0.1.2
	github.com/refraction-networking/utls v1.3.3
	github.com/sirupsen/logrus v1.9.3
	github.com/stretchr/testify v1.8.4
	github.com/xtaci/kcp-go v5.4.20+incompatible
	gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/goptlib v1.5.0
	golang.org/x/crypto v0.26.0
	golang.org/x/net v0.28.0
	golang.org/x/sys v0.23.0
	google.golang.org/grpc v1.59.0
	google.golang.org/protobuf v1.33.0
)

require (
	filippo.io/bigmod v0.0.1 // indirect
	github.com/andybalholm/brotli v1.0.5 // indirect
	github.com/cespare/xxhash/v2 v2.2.0 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/dchest/siphash v1.2.3 // indirect
	github.com/dgryski/go-rendezvous v0.0.0-20200823014737-9f7001d12a5f // indirect
	github.com/gaukas/godicttls v0.0.4 // indirect
	github.com/go-task/slim-sprig v0.0.0-20230315185526-52ccab3ef572 // indirect
	github.com/google/pprof v0.0.0-20211214055906-6f57359322fd // indirect
	github.com/klauspost/compress v1.16.7 // indirect
	github.com/klauspost/cpuid/v2 v2.1.1 // indirect
	github.com/klauspost/reedsolomon v1.11.8 // indirect
	github.com/onsi/ginkgo/v2 v2.9.5 // indirect
	github.com/oschwald/maxminddb-golang v1.12.0 // indirect
	github.com/pion/randutil v0.1.0 // indirect
	github.com/pion/transport/v3 v3.0.1 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/quic-go/quic-go v0.47.0 // indirect
	github.com/sergeyfrolov/bsbuffer v0.0.0-20180903213811-94e85abb8507 // indirect
	github.com/templexxx/cpufeat v0.0.0-20180724012125-cef66df7f161 // indirect
	github.com/templexxx/xor v0.0.0-20191217153810-f85b25db303b // indirect
	github.com/tjfoc/gmsm v1.4.1 // indirect
	github.com/xtaci/lossyconn v0.0.0-20200209145036-adba10fffc37 // indirect
	go.uber.org/mock v0.4.0 // indirect
	golang.org/x/exp v0.0.0-20240506185415-9bf2ced13842 // indirect
	golang.org/x/mod v0.17.0 // indirect
	golang.org/x/text v0.17.0 // indirect
	golang.org/x/tools v0.21.1-0.20240508182429-e35e4ccd0d2d // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/pion/dtls/v2 => github.com/mingyech/dtls/v2 v2.0.0-20231127190216-63a98eeae997

replace github.com/pion/transport/v2 => github.com/mingyech/transport/v2 v2.0.0
