package handler

import (
	"bytes"
	"encoding/base64"
	"encoding/gob"
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
)

type realbody struct {
	Method  string            `json:"method"`
	Url     string            `json:"url"`
	Headers map[string]string `json:"headers"`
	Cookies map[string]string `json:"cookies"`
	Params  map[string]string `json:"params"`
	Data    []byte            `json:"data"`
}

type rspbody struct {
	IsBase64Encoded bool
	StatusCode      int
	Headers         map[string]string
	Data            string
}

func ToUtf8(to_decode string) string {
	to_decode_buf := []byte(to_decode)
	buf := make([]rune, len(to_decode_buf))
	for i, b := range to_decode_buf {
		buf[i] = rune(b)
	}
	return string(buf)
}

func Proxyweb(w http.ResponseWriter, r *http.Request) {

	if r.Method == "POST" {

		log.Println(r.Header.Get("content-type"))
		log.Println(r.Header.Get("Content-Encoding"))

		rbody, _ := ioutil.ReadAll(r.Body)
		rb := realbody{}
		err := json.Unmarshal([]byte(rbody), &rb)
		if err != nil {
			log.Println(err)
		}
		log.Println(rb.Method)
		log.Println(rb.Url)

		log.Println("Decoding headers:")
		for k, v := range rb.Headers {
			log.Println(k, "=", v)
		}

		log.Println("Decoding cookies:")
		for k, v := range rb.Cookies {
			log.Println(k, "=", v)
		}

		log.Println("Decoding url params:")
		for k, v := range rb.Params {
			log.Println(k, "=", v)
		}

		reqbody := make([]byte, base64.StdEncoding.DecodedLen(len(rb.Data)))

		n, _ := base64.StdEncoding.Decode(reqbody, rb.Data)
		reqbody = reqbody[:n]
		client := &http.Client{}
		req, err := http.NewRequest(rb.Method, rb.Url, bytes.NewReader(reqbody))
		for k, v := range rb.Headers {
			req.Header.Add(k, v)
		}

		resp, err := client.Do(req)
		log.Println("Getting result:")
		log.Println(resp.Status)
		log.Println(resp)

		//	rspcontent := rspbody{}

		//	buff := new(bytes.Buffer)
		var buff bytes.Buffer
		enc := gob.NewEncoder(&buff)
		enc.Encode(resp)

		//	binary.Write(buff, binary.BigEndian, resp)
		rsp := buff.Bytes()
		//	dst := make([]byte, base64.StdEncoding.EncodedLen(len(rsp)))
		//	base64.StdEncoding.Encode(dst, rsp)                          //对返回的http响应的所有字节内容进行base64b编码，得到dst字节切片

		dst := base64.StdEncoding.EncodeToString(rsp)
		dst = ToUtf8(dst)
		//	log.Println(dst)

		//	rspcontent.IsBase64Encoded = false
		//	rspcontent.StatusCode = 200
		//	rspcontent.Data = string(dst)
		//	rspcontent.Data = append(rspcontent.Data, dst...)
		//	log.Println(rspcontent)

		//	buff2 := new(bytes.Buffer)
		//	binary.Write(buff2, binary.BigEndian, rspcontent)
		//	enc.Encode(rspcontent)

		w.Header().Del("Accept-Encoding")

		w.WriteHeader(http.StatusOK)

		w.Write([]byte(dst))

	}

}
