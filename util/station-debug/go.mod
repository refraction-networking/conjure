module zmqsub

go 1.20

require (
	github.com/pebbe/zmq4 v1.2.10
	github.com/refraction-networking/conjure v0.7.8
	google.golang.org/protobuf v1.31.0
)

require (
	github.com/BurntSushi/toml v1.3.2 // indirect
	github.com/cespare/xxhash/v2 v2.2.0 // indirect
	github.com/dchest/siphash v1.2.3 // indirect
	github.com/dgryski/go-rendezvous v0.0.0-20200823014737-9f7001d12a5f // indirect
	github.com/go-redis/redis/v8 v8.11.5 // indirect
	github.com/google/go-cmp v0.5.9 // indirect
	github.com/hashicorp/golang-lru v1.0.2 // indirect
	github.com/mroth/weightedrand v1.0.0 // indirect
	github.com/oschwald/geoip2-golang v1.9.0 // indirect
	github.com/oschwald/maxminddb-golang v1.12.0 // indirect
	github.com/pelletier/go-toml v1.9.5 // indirect
	github.com/refraction-networking/ed25519 v0.1.2 // indirect
	github.com/refraction-networking/obfs4 v0.1.2 // indirect
	gitlab.torproject.org/tpo/anti-censorship/pluggable-transports/goptlib v1.5.0 // indirect
	golang.org/x/crypto v0.15.0 // indirect
	golang.org/x/sys v0.14.0 // indirect
)

replace github.com/pion/dtls/v2 => github.com/mingyech/dtls/v2 v2.0.0-20231127190216-63a98eeae997

replace github.com/pion/transport/v2 => github.com/mingyech/transport/v2 v2.0.0

replace github.com/refraction-networking/conjure => ../../
