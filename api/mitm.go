package handler

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
)

func Proxyweb(w http.ResponseWriter, r *http.Request) {
	log.Println(r.Method)
	if r.Method == "POST" {
		rbody, _ := ioutil.ReadAll(r.Body)
		log.Println(rbody)
		fmt.Print(w, "hello")

	}

}
