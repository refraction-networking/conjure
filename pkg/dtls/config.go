package dtls

type Config struct {
	PSK  []byte
	SCTP SCTPType
}

type SCTPType int

const (
	ServerAccept SCTPType = iota
	ClientOpen
)
