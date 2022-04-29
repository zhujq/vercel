package handler

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
)

type realbody struct {
	method  string `json:"method"`
	url     string `json:"url"`
	headers string `json:"headers"`
	cookies string `json:"cookies"`
	params  string `json:"params"`
	data    string `json:"data"`
}

func Proxyweb(w http.ResponseWriter, r *http.Request) {
	log.Println(r.Method)
	if r.Method == "POST" {
		rbody, _ := ioutil.ReadAll(r.Body)
		rb := realbody{}
		json.Unmarshal([]byte(rbody), &rb)
		log.Println(rb)
		fmt.Print(w, "hello")

	}

}
