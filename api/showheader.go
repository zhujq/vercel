package handler

import (
	"fmt"
	"net/http"
)

func DisplayHeadersHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Method: %s URL: %s Protocol: %s \n", r.Method, r.URL, r.Proto)
	fmt.Fprintf(w, "Host = %q\n", r.Host)
	fmt.Fprintf(w, "RemoteAddr= %q\n", r.RemoteAddr)
	// 遍历所有请求头
	for k, v := range r.Header {
		fmt.Fprintf(w, "Header field %q, Value %q\n", k, v)
	}

}
