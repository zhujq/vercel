package handler

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
)

type realbody struct {
	method string `json:"method"`
	url    string `json:"url"`
}

func Proxyweb(w http.ResponseWriter, r *http.Request) {
	log.Println(r.Method)
	if r.Method == "POST" {
		rbody, _ := ioutil.ReadAll(r.Body)
		rb := realbody{}
		json.Unmarshal([]byte(rbody), &rb)
		log.Println(rb.method)
		fmt.Print(w, "hello")

	}

}
