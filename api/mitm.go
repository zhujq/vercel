package handler

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
)

func Proxyweb(w http.ResponseWriter, r *http.Request) {
	if r.Method == "post" {
		rbody, _ := ioutil.ReadAll(r.Body)
		log.Println(rbody)
		fmt.Print(w, "hello")

	}

}
