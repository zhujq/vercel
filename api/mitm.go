package handler

import (
	"fmt"
	"io/ioutil"
	"net/http"
)

func Proxyweb(w http.ResponseWriter, r *http.Request) {
	if r.Method == "post" {
		rbody, _ := ioutil.ReadAll(r.Body)

		fmt.Print(w, "%s", rbody)

	}

}
