package tworeqresp

import (
	"bytes"
	"fmt"
	"time"

	pb "github.com/refraction-networking/conjure/proto"
	"google.golang.org/protobuf/proto"
)

var interval = 30 * time.Second

type oneresponder interface {
	RecvAndRespond(getResponse func([]byte) ([]byte, error)) error
	Close() error
}

type Responder struct {
	parent oneresponder
	parts  map[[idLen]byte]*timedData
}

func NewResponder(parent oneresponder) (*Responder, error) {
	return &Responder{
		parent: parent,
		parts:  make(map[[idLen]byte]*timedData),
	}, nil
}

type timedData struct {
	data   [][]byte
	expiry time.Time
}

func (r *Responder) RecvAndRespond(parentGetResponse func([]byte) ([]byte, error)) error {
	ticker := time.NewTicker(interval)
	getResponse := func(data []byte) ([]byte, error) {
		select {
		case <-ticker.C:
			for key, data := range r.parts {
				if time.Now().After(data.expiry) {
					delete(r.parts, key)
				}
			}
		default:
		}

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
			r.parts[*partId] = &timedData{
				data:   make([][]byte, partIn.GetTotalParts()),
				expiry: time.Now().Add(interval),
			}
		}

		if int(partIn.GetTotalParts()) != len(r.parts[*partId].data) {
			return nil, fmt.Errorf("invalid total parts")
		}

		if int(partIn.GetPartNum()) >= len(r.parts[*partId].data) {
			return nil, fmt.Errorf("part number out of bound")
		}

		r.parts[*partId].data[partIn.GetPartNum()] = partIn.GetData()

		waiting := false
		for _, part := range r.parts[*partId].data {
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
		for _, part := range r.parts[*partId].data {
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
