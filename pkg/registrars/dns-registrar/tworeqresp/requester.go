package tworeqresp

type onerequester interface {
	RequestAndRecv(sendBytes []byte) ([]byte, error)
}

type Requester struct {
	parent onerequester
}
