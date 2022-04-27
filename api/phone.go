package handler

import (

	//	"fmt"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	//	"path"
	//	"runtime"
	"strings"
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

const (
	CMCC               byte = iota + 0x01 //中国移动
	CUCC                                  //中国联通
	CTCC                                  //中国电信
	CTCC_v                                //电信虚拟运营商
	CUCC_v                                //联通虚拟运营商
	CMCC_v                                //移动虚拟运营商
	INT_LEN            = 4
	CHAR_LEN           = 1
	HEAD_LENGTH        = 8
	PHONE_INDEX_LENGTH = 9
	PHONE_DAT          = "telephone.dat"
)

type PhoneRecord struct {
	PhoneNum string
	Province string
	City     string
	ZipCode  string
	AreaZone string
	CardType string
}

var (
	content     []byte
	CardTypemap = map[byte]string{
		CMCC:   "中国移动",
		CUCC:   "中国联通",
		CTCC:   "中国电信",
		CTCC_v: "中国电信虚拟运营商",
		CUCC_v: "中国联通虚拟运营商",
		CMCC_v: "中国移动虚拟运营商",
	}
	total_len, firstoffset int32
)

func init() {

}

func (pr PhoneRecord) String() string {
	return fmt.Sprintf("PhoneNum: %s\nAreaZone: %s\nCardType: %s\nCity: %s\nZipCode: %s\nProvince: %s\n", pr.PhoneNum, pr.AreaZone, pr.CardType, pr.City, pr.ZipCode, pr.Province)
}

func get4(b []byte) int32 {
	if len(b) < 4 {
		return 0
	}
	return int32(b[0]) | int32(b[1])<<8 | int32(b[2])<<16 | int32(b[3])<<24
}

func getN(s string) (uint32, error) {
	var n, cutoff, maxVal uint32
	i := 0
	base := 10
	cutoff = (1<<32-1)/10 + 1
	maxVal = 1<<uint(32) - 1
	for ; i < len(s); i++ {
		var v byte
		d := s[i]
		switch {
		case '0' <= d && d <= '9':
			v = d - '0'
		case 'a' <= d && d <= 'z':
			v = d - 'a' + 10
		case 'A' <= d && d <= 'Z':
			v = d - 'A' + 10
		default:
			return 0, errors.New("invalid syntax")
		}
		if v >= byte(base) {
			return 0, errors.New("invalid syntax")
		}

		if n >= cutoff {
			// n*base overflows
			n = (1<<32 - 1)
			return n, errors.New("value out of range")
		}
		n *= uint32(base)

		n1 := n + uint32(v)
		if n1 < n || n1 > maxVal {
			// n+v overflows
			n = (1<<32 - 1)
			return n, errors.New("value out of range")
		}
		n = n1
	}
	return n, nil
}

func totalRecord() int32 {
	return (int32(len(content)) - firstRecordOffset()) / PHONE_INDEX_LENGTH
}

func firstRecordOffset() int32 {
	return get4(content[INT_LEN : INT_LEN*2])
}

// 二分法查询phone数据
func find(phone_num string) (pr *PhoneRecord, err error) {

	/*	dir := os.Getenv("PHONE_DATA_DIR")
		if dir == "" {
			_, fulleFilename, _, _ := runtime.Caller(0)
			dir = path.Dir(fulleFilename)
		}
	*/
	content, err = ioutil.ReadFile("./telephone.dat")
	if err != nil {
		panic(err)
	}
	total_len = int32(len(content))
	firstoffset = get4(content[INT_LEN : INT_LEN*2])

	if len(phone_num) < 7 || len(phone_num) > 11 {
		return nil, errors.New("illegal phone length")
	}

	var left int32
	phone_seven_int, err := getN(phone_num[0:7])
	if err != nil {
		return nil, errors.New("illegal phone number")
	}
	phone_seven_int32 := int32(phone_seven_int)
	right := (total_len - firstoffset) / PHONE_INDEX_LENGTH
	for {
		if left > right {
			break
		}
		mid := (left + right) / 2
		offset := firstoffset + mid*PHONE_INDEX_LENGTH
		if offset >= total_len {
			break
		}
		cur_phone := get4(content[offset : offset+INT_LEN])
		record_offset := get4(content[offset+INT_LEN : offset+INT_LEN*2])
		card_type := content[offset+INT_LEN*2 : offset+INT_LEN*2+CHAR_LEN][0]
		switch {
		case cur_phone > phone_seven_int32:
			right = mid - 1
		case cur_phone < phone_seven_int32:
			left = mid + 1
		default:
			cbyte := content[record_offset:]
			end_offset := int32(bytes.Index(cbyte, []byte("\000")))
			data := bytes.Split(cbyte[:end_offset], []byte("|"))
			card_str, ok := CardTypemap[card_type]
			if !ok {
				card_str = "未知电信运营商"
			}
			pr = &PhoneRecord{
				PhoneNum: phone_num,
				Province: string(data[0]),
				City:     string(data[1]),
				ZipCode:  string(data[2]),
				AreaZone: string(data[3]),
				CardType: card_str,
			}
			return
		}
	}
	return nil, errors.New("phone's data not found")
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

		phoneresult, err := find(phonenum)

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
