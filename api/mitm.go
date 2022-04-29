package handler

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
)

type realbody struct {
	Method string `json:"method"`
	Url    string `json:"url"`
}

func Proxyweb(w http.ResponseWriter, r *http.Request) {

	if r.Method == "POST" {
		rbody, _ := ioutil.ReadAll(r.Body)
		rb := realbody{}
		err := json.Unmarshal([]byte(rbody), &rb)
		if err != nil {
			log.Println(err)
		}
		log.Println(rb.method)
		fmt.Print(w, "hello")

	}

}
