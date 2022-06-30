module github.com/refraction-networking/conjure

go 1.16

require (
	git.torproject.org/pluggable-transports/goptlib.git v1.2.0
	github.com/BurntSushi/toml v0.4.1
	github.com/go-redis/redis/v8 v8.11.4
	github.com/gorilla/mux v1.8.0
	github.com/mroth/weightedrand v0.4.1
	github.com/pebbe/zmq4 v1.2.7
	github.com/pelletier/go-toml v1.9.4
	github.com/refraction-networking/gotapdance v0.0.0-20211215234154-01ce7114837a
	github.com/refraction-networking/utls v1.0.0
	github.com/stretchr/testify v1.7.1
	gitlab.com/yawning/obfs4.git v0.0.0-20220204003609-77af0cba934d
	golang.org/x/crypto v0.0.0-20220411220226-7b82a4e95df4
	google.golang.org/grpc v1.41.0
	google.golang.org/protobuf v1.28.0
)

replace github.com/refraction-networking/gotapdance => github.com/mingyech/gotapdance v1.2.1-0.20220630175922-0d2241058506
