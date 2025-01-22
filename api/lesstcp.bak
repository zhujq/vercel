package handler

import (
	"log"
	"net/http"
)

func Handler(w http.ResponseWriter, r *http.Request) {

	hj, ok := w.(http.Hijacker)
	if !ok {
		log.Println("Hijacker error")
		http.Error(w, "webserver doesn't support hijacking", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hj.Hijack()
	if err != nil {
		log.Println("Hijacker Conn error")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	//log.Println("hj.hijacker is ok")
	defer clientConn.Close()
	clientConn.Write([]byte("Hello world"))
	return

}
