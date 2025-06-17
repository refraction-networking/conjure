package tworeqresp

import (
	"bytes"
	"fmt"
	"sync"
	"time"

	pb "github.com/refraction-networking/conjure/proto"
	"google.golang.org/protobuf/proto"
)

var interval = 30 * time.Second

const maxChunks = 10

type oneresponder interface {
	RecvAndRespond(getResponse func([]byte) ([]byte, error)) error
	Close() error
}

type Responder struct {
	parent oneresponder
	parts  map[[idLen]byte]*timedData
	mutex  sync.Mutex
}

func NewResponder(parent oneresponder) (*Responder, error) {
	r := &Responder{
		parent: parent,
		parts:  make(map[[idLen]byte]*timedData),
		mutex:  sync.Mutex{},
	}
	go r.gc()
	return r, nil
}

func (r *Responder) gc() {
	ticker := time.NewTicker(interval)

	for range ticker.C {
		func() {
			r.mutex.Lock()
			defer r.mutex.Unlock()
			for key, data := range r.parts {
				if time.Now().After(data.expiry) {
					delete(r.parts, key)
				}
			}
		}()
	}

}

type timedData struct {
	data   [][]byte
	expiry time.Time
	mutex  sync.Mutex
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

		if *partIn.TotalParts > maxChunks {
			return nil, fmt.Errorf("request over max chunk limit")
		}

		r.mutex.Lock()
		regData, ok := r.parts[*partId]

		if !ok {
			r.parts[*partId] = &timedData{
				data:   make([][]byte, partIn.GetTotalParts()),
				expiry: time.Now().Add(interval),
				mutex:  sync.Mutex{},
			}
			regData = r.parts[*partId]
		}
		r.mutex.Unlock()

		buf, waiting, err := func() ([]byte, bool, error) {
			regData.mutex.Lock()
			defer regData.mutex.Unlock()
			if int(partIn.GetTotalParts()) != len(regData.data) {
				return nil, false, fmt.Errorf("invalid total parts")
			}

			if int(partIn.GetPartNum()) >= len(regData.data) {
				return nil, false, fmt.Errorf("part number out of bound")
			}

			regData.data[partIn.GetPartNum()] = partIn.GetData()

			waiting := false
			for _, part := range regData.data {
				if part == nil {
					waiting = true
					break
				}
			}
			if waiting {
				return nil, true, nil
			}

			var buffer bytes.Buffer
			for _, part := range regData.data {
				buffer.Write(part)
			}

			return buffer.Bytes(), false, nil
		}()

		if err != nil {
			return nil, err
		}

		if waiting {
			resp := &pb.DnsPartResp{Waiting: proto.Bool(true)}
			respBytes, err := proto.Marshal(resp)
			if err != nil {
				return nil, fmt.Errorf("error marshal resp: %v", err)
			}

			return respBytes, nil
		}

		res, err := parentGetResponse(buf)
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
