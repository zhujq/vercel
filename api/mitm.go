package handler

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
)

type realbody struct {
	Method  string `json:"method"`
	Url     string `json:"url"`
	Headers string `json:"headers"`
	Cookies string `json:"cookies"`
	Params  string `json:"params"`
}

func Proxyweb(w http.ResponseWriter, r *http.Request) {

	if r.Method == "POST" {
		rbody, _ := ioutil.ReadAll(r.Body)
		rb := realbody{}
		err := json.Unmarshal([]byte(rbody), &rb)
		if err != nil {
			log.Println(err)
		}
		log.Println(rb)
		fmt.Print(w, "hello")

	}

}
