package tworeqresp

import (
	"crypto/rand"
	"fmt"

	pb "github.com/refraction-networking/conjure/proto"
	"google.golang.org/protobuf/proto"
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
		toSend := &pb.DnsPartReq{Id: id[:], PartNum: proto.Uint32(uint32(i)), Data: partBytes}
		toSendBytes, err := proto.Marshal(toSend)
		if err != nil {
			return nil, fmt.Errorf("error marshal part %v: %v", i, err)
		}

		respBytes, err := r.parent.RequestAndRecv(toSendBytes)
		if err != nil {
			return nil, fmt.Errorf("error request part %v: %v", i, err)
		}

		resp := &pb.DnsPartResp{}
		err = proto.Unmarshal(respBytes, resp)
		if err != nil {
			return nil, fmt.Errorf("error unmarshal response: %v", err)
		}

		if resp.GetWaiting() {
			continue
		}

		return resp.GetData(), nil
	}

	return nil, fmt.Errorf("no response")
}
