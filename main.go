package main

import (
	"log"
	"net/http"
	"os"
	"time"
)

const version uint32 = 1

const (
	blacklistPath = "./blacklist"

	badReqsLogPath = "./badreqs"
	badReqsLogSize = 1048576
	goodReqsLogPath = "./reqs"
	goodReqsLogSize = 262144
	generalLogPath = "./log"
	generalLogSize = 1048576

	maxMessagesPerUser = 40
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
		// https://web.archive.org/web/20150915083011/http://www.opensource.apple.com/source/tcpdump/tcpdump-32/tcpdump/tcpdump.c
		err = server.ListenAndServeTLS("cert.pem", "key.pem")
		h.general.Log.Println(err)
	}
	log.Println(err)
}
