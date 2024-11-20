package tworeqresp

import (
	"bytes"
	"fmt"

	pb "github.com/refraction-networking/conjure/proto"
	"google.golang.org/protobuf/proto"
)

type oneresponder interface {
	RecvAndRespond(getResponse func([]byte) ([]byte, error)) error
	Close() error
}

type Responder struct {
	parent oneresponder
	parts  map[[idLen]byte][][]byte
}

func NewResponder(parent oneresponder) (*Responder, error) {
	return &Responder{
		parent: parent,
		parts:  make(map[[idLen]byte][][]byte),
	}, nil
}

func (r *Responder) RecvAndRespond(parentGetResponse func([]byte) ([]byte, error)) error {
	getResponse := func(data []byte) ([]byte, error) {
		partIn := &pb.DnsPartReq{}
		err := proto.Unmarshal(data, partIn)
		if err != nil {
			return nil, fmt.Errorf("error umarshal part: %v", err)
		}

		if len(partIn.GetId()) != idLen {
			return nil, fmt.Errorf("invalid part ID")
		}

		partId := (*[idLen]byte)(partIn.GetId())

		if _, ok := r.parts[*partId]; !ok {
			r.parts[*partId] = make([][]byte, partIn.GetTotalParts())
		}

		if int(partIn.GetTotalParts()) != len(r.parts[*partId]) {
			return nil, fmt.Errorf("invalid total parts")
		}

		if int(partIn.GetPartNum()) >= len(r.parts[*partId]) {
			return nil, fmt.Errorf("part number out of bound")
		}

		r.parts[*partId][partIn.GetPartNum()] = partIn.GetData()

		waiting := false
		for _, part := range r.parts[*partId] {
			if part == nil {
				waiting = true
				break
			}
		}

		if waiting {
			resp := &pb.DnsPartResp{Waiting: proto.Bool(true)}
			respBytes, err := proto.Marshal(resp)
			if err != nil {
				return nil, fmt.Errorf("error marshal resp: %v", err)
			}

			return respBytes, nil
		}

		var buffer bytes.Buffer
		for _, part := range r.parts[*partId] {
			buffer.Write(part)
		}
		res, err := parentGetResponse(buffer.Bytes())
		if err != nil {
			return nil, fmt.Errorf("error from parent getResponse: %v", err)
		}

		resp := &pb.DnsPartResp{Waiting: proto.Bool(false), Data: res}

		respBytes, err := proto.Marshal(resp)
		if err != nil {
			return nil, fmt.Errorf("error marshal resp: %v", err)
		}

		return respBytes, nil

	}
	return r.parent.RecvAndRespond(getResponse)
}

// Close closes the parent transport
func (r *Responder) Close() error {
	return r.parent.Close()
}
