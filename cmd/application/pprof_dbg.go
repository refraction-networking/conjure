//go:build debug

package main

import (
	"log"
	"net/http"
	_ "net/http/pprof"
)

func startPProf() {
	go func() {
		log.Println(http.ListenAndServe("localhost:6060", nil))
	}()
}
