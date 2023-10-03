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
	mtu    uint
}

func NewRequester(parent onerequester, mtu uint) (*Requester, error) {
	return &Requester{parent: parent, mtu: mtu}, nil
}

func (r *Requester) RequestAndRecv(sendBytes []byte) ([]byte, error) {

	id := [idLen]byte{}
	_, err := rand.Read(id[:])
	if err != nil {
		return nil, fmt.Errorf("error generating id: %v", err)
	}

	parts := splitIntoChunks(sendBytes, int(r.mtu))

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

func splitIntoChunks(data []byte, mtu int) [][]byte {
	var chunks [][]byte

	for i := 0; i < len(data); i += mtu {
		end := i + mtu

		if end > len(data) {
			end = len(data)
		}

		chunks = append(chunks, data[i:end])
	}

	return chunks
}
