package handler

import (

	//	"fmt"
	"encoding/json"
	"log"
	"net/http"
	"strings"

	"./phonedata"
)

type ResBody struct {
	Status   string `json:"status"`
	PhoneNum string `json:"PhoneNum"`
	Province string `json:"Province"`
	City     string `json:"City "`
	ZipCode  string `json:"ZipCode"`
	AreaZone string `json:"AreaZone"`
	CardType string `json:"CardType"`
}

func Getphone(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	phonenum := r.FormValue("phonenum")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	if phonenum == "" {
		w.Write([]byte("欢迎使用中国电话号码查询系统，请在网址后输入 /?phonenum=电话号码 查询!"))
	} else {

		var message ResBody
		message.PhoneNum = phonenum

		if strings.HasPrefix(phonenum, "86") {

			phonenum = strings.TrimPrefix(phonenum, "86")

		}

		phoneresult, err := phonedata.Find(phonenum)

		if err != nil {
			log.Println("error:", err)
			w.Write([]byte("查询不到你输入的中国号码信息!"))
			return
		}

		message.Status = "success"
		message.Province = phoneresult.Province
		message.City = phoneresult.City
		message.ZipCode = phoneresult.ZipCode
		message.AreaZone = phoneresult.AreaZone
		message.CardType = phoneresult.CardType
		js, _ := json.Marshal(message)
		w.Write(js)
	}

	return
}
