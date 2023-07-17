package dtls

import "net"

type Config struct {
	PSK             []byte
	SCTP            SCTPType
	LogUnregistered func(*net.IP)
}

type SCTPType int

const (
	ServerAccept SCTPType = iota
	ClientOpen
)
