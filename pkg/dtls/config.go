package dtls

import "net"

type Config struct {
	PSK         []byte
	SCTP        SCTPType
	LogAuthFail func(*net.IP)
	LogOther    func(*net.IP)
}

type SCTPType int

const (
	ServerAccept SCTPType = iota
	ClientOpen
)
