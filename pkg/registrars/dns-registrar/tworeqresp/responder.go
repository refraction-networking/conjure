package tworeqresp

type oneresponder interface {
	RecvAndRespond(getResponse func([]byte) ([]byte, error)) error
}

type Responder struct {
	parent oneresponder
}
