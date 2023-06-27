package msgformat

import (
	"reflect"
	"testing"
)

func TestRequestFormat(t *testing.T) {
	msg := []byte("blablabla")
	for i := 0; i < 3; i++ {
		request := msg[0:i]
		requestBuf, err := AddRequestFormat(request)
		if err != nil {
			t.Errorf("err: [%v]", err)
		}
		requestedMsg, err := RemoveRequestFormat(requestBuf)
		if err != nil {
			t.Errorf("err: [%v]", err)
		}
		if !reflect.DeepEqual(requestedMsg, request) {
			t.Errorf("request [%v] != requestedMsg [%v]", request, requestedMsg)
		}
	}
}

func TestResponseFormat(t *testing.T) {
	msg := []byte("blablabla")
	for i := 0; i < 3; i++ {
		response := msg[0:i]
		responseBuf, err := AddResponseFormat(response)
		if err != nil {
			t.Errorf("err: [%v]", err)
		}
		responseedMsg, err := RemoveResponseFormat(responseBuf)
		if err != nil {
			t.Errorf("err: [%v]", err)
		}
		if !reflect.DeepEqual(responseedMsg, response) {
			t.Errorf("response [%v] != responseedMsg [%v]", response, responseedMsg)
		}
	}
}
