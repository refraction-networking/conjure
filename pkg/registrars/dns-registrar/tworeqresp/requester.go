package tworeqresp

import (
	"crypto/rand"
	"fmt"
)

const idLen = 8

type onerequester interface {
	RequestAndRecv(sendBytes []byte) ([]byte, error)
}

type Requester struct {
	parent onerequester
}

func (r *Requester) RequestAndRecv(sendBytes []byte) ([]byte, error) {
	firstHalf := sendBytes[:len(sendBytes)/2]
	secondHalf := sendBytes[len(sendBytes)/2:]

	id := [idLen]byte{}
	_, err := rand.Read(id[:])
	if err != nil {
		return nil, fmt.Errorf("error generating id: %v", err)
	}

	parts := [][]byte{firstHalf, secondHalf}

	for i, partBytes := range parts {
		toSend := part{id: id, partNum: uint8(i), data: partBytes}
		toSendBytes, err := toSend.marshal()
		if err != nil {
			return nil, fmt.Errorf("error marshal part %v: %v", i, err)
		}

		respBytes, err := r.parent.RequestAndRecv(toSendBytes)
		if err != nil {
			return nil, fmt.Errorf("error request part %v: %v", i, err)
		}
	}

	return nil, fmt.Errorf("no response")
}

type part struct {
	id      [idLen]byte
	partNum uint8
	data    []byte
}

func (p *part) marshal() ([]byte, error) {
	if p.data == nil {
		return nil, fmt.Errorf("data cannot be nil")
	}

	result := make([]byte, 0, idLen+1+len(p.data))

	result = append(result, p.id[:]...)

	result = append(result, p.partNum)

	result = append(result, p.data...)

	return result, nil
}

func (p *part) unmarshal(data []byte) error {
	if len(data) < idLen+1 {
		return fmt.Errorf("data is too short to unmarshal")
	}

	copy(p.id[:], data[:idLen])

	p.partNum = data[idLen]

	p.data = data[idLen+1:]

	return nil
}
