package handler

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
)

type realbody struct {
	Method  string       `json:"method"`
	Url     string       `json:"url"`
	Headers string       `json:"headers"`
	Cookies *http.Cookie `json:"cookies"`
	Params  *url.Values  `json:"params"`
	Data    []byte       `json:"data"`
}

func Proxyweb(w http.ResponseWriter, r *http.Request) {

	if r.Method == "POST" {
		rbody, _ := ioutil.ReadAll(r.Body)
		rb := realbody{}
		err := json.Unmarshal([]byte(rbody), &rb)
		if err != nil {
			log.Println(err)
		}
		log.Println(rb.Method)
		log.Println(rb.Url)

		log.Println("Decoding headers:")
		/*	for k, v := range *rb.Headers {
				log.Println(k, "=", v)
			}
		*/
		log.Println(rb.Headers)
		log.Println("Decoding cookies:")
		log.Println(*rb.Cookies)

		log.Println("Decoding url params:")
		for k, v := range *rb.Params {
			log.Println(k, "=", v)
		}

		reqbody, _ := base64.StdEncoding.DecodeString(string(rb.Data))
		client := &http.Client{}
		req, err := http.NewRequest(rb.Method, rb.Url, bytes.NewReader(reqbody))
		//	req.Header = *rb.Headers
		req.AddCookie(rb.Cookies)
		resp, err := client.Do(req)
		log.Println("Getting result:")
		log.Println(resp.Status)
		log.Println(resp.ContentLength)

		buff := new(bytes.Buffer)
		binary.Write(buff, binary.BigEndian, resp)
		rsp := buff.Bytes()
		dst := make([]byte, base64.StdEncoding.EncodedLen(len(rsp)))
		base64.StdEncoding.Encode(dst, rsp)
		w.WriteHeader(200)
		w.Write(buff.Bytes())

	}

}
