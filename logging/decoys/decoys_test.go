package decoys

import (
	"encoding/hex"
	"testing"
)

func TestBuildAssets(t *testing.T) {
	a := Assets()
	for k, v := range a.decoys {
		t.Logf("%v:%+v\n", k, v)
	}
}

func TestGetDecoys(t *testing.T) {
	ss, _ := hex.DecodeString("7c8ef3fa7688d0b9beed7d269f9b428745c8cc12e2fb721c9f21f3ef35e9b312")
	d := SelectDecoys(ss, 0, 5, both)
	for k, v := range d {
		t.Logf("%v:%+v\n", k, v)
	}
}
