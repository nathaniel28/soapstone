package main

import (
	"log"
	"net/http"
	"os"
	"time"
)

//3d80-dc1f

const version uint32 = 0

const (
	blacklistPath = "./blacklist"

	badReqsLogPath = "./badreqs"
	badReqsLogSize = 1048576
	goodReqsLogPath = "./reqs"
	goodReqsLogSize = 262144
	generalLogPath = "./log"
	generalLogSize = 1048576
)

func main() {
	name, err := os.ReadFile("dbname")
	if err != nil {
		log.Fatal(err)
	}
	h, err := newHandler(string(name))
	if err == nil {
		defer h.destroy()
		server := &http.Server{
			Addr:           "0.0.0.0:443",
			Handler:        h,
			ReadTimeout:    60 * time.Second,
			WriteTimeout:   60 * time.Second,
			MaxHeaderBytes: 1 << 14,
		}
		// TODO drop root
		err = server.ListenAndServeTLS("cert.pem", "key.pem")
		h.general.Log.Println(err)
	}
	log.Println(err)
}
