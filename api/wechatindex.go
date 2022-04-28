package handler

import (
	"database/sql"
	"encoding/json"
	"log"

	//	"io"
	"net/http"
	"strings"

	_ "github.com/go-sql-driver/mysql"
	//	"database/sql"
)

type ResBody struct {
	Status      string `json:"status"`
	Mediatype   string `json:"mediatype"`
	Mediaid     string `json:"mediaid"`
	Mediatitle  string `json:"mediatitle"`
	Mediaurl    string `json:"mediaurl"`
	Mediadigest string `json:"mediadigest"`
	Mediathumb  string `json:"mediathumb"`
}

func writefailed(w http.ResponseWriter, r *http.Request) {
	var m = ResBody{
		Status:      "failed",
		Mediatype:   "",
		Mediaid:     "",
		Mediaurl:    "",
		Mediadigest: "",
		Mediathumb:  "",
	}
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotFound)
	js, _ := json.Marshal(m)
	w.Write(js)
}

func Getindex(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	keyword := r.FormValue("keyword")
	querytype := "default"
	log.Println(keyword)

	var message = ResBody{
		Status:      "failed",
		Mediatype:   "",
		Mediaid:     "",
		Mediaurl:    "",
		Mediadigest: "",
		Mediathumb:  "",
	}

	if keyword == "" {
		log.Println("wechat-index ERROR: 没有提供keyword")
		writefailed(w, r)
		return
	}

	Dbconn := "zhujq:Juju1234@tcp(wechat.zhujq.ga:3306)/wechat"
	Dbconn += "?tls=preferred" //2021-10-21 默认mysql ssl连接
	db, err := sql.Open("mysql", Dbconn)

	defer db.Close()
	err = db.Ping()
	if err != nil {
		log.Println("wechat-index conn to mysql error:", err)
		writefailed(w, r)
		return
	}

	if strings.HasPrefix(keyword, "poem:+") {

		keyword = strings.Replace(keyword, "poem:+", "", -1)
		querytype = "poem"

	}

	for { //去掉Keyword首尾空格
		if strings.HasPrefix(keyword, " ") || strings.HasSuffix(keyword, " ") {
			keyword = strings.TrimPrefix(keyword, " ")
			keyword = strings.TrimSuffix(keyword, " ")
		} else {
			break
		}

	}

	var sqlstr string = ""

	if querytype == "default" {

		switch keyword {
		case "help", "帮助":
			sqlstr = `select mediatype,mediaid,title,url,digest,thumbmedia from media where title = "公众号使用帮助" and mediatype = "news"  order by rand() limit 1; `
		case "about me", "关于我", "aboutme":
			sqlstr = `select mediatype,mediaid,title,url,digest,thumbmedia from media where title = "about me" and mediatype = "news" order by rand() limit 1; `
		case "list", "文章", "文章列表", "ls":
			sqlstr = `select mediatype,mediaid,title,url,digest,thumbmedia from media where title = "原创文章列表" and mediatype = "news" order by rand() limit 1; `
		default:
			keyword = strings.ReplaceAll(keyword, ` `, `%" and title like "%`)
			if strings.LastIndex(keyword, "+") == (len(keyword)-2) && strings.LastIndex(keyword, "+") != -1 && len(keyword) >= 3 { //关键字含有+ 且 倒数第二字节是+
				lastword := string(keyword[len(keyword)-1:])
				prefix := string(keyword[0 : len(keyword)-2])
				switch lastword {
				case "V", "v":
					sqlstr = `select a.mediatype,a.mediaid,a.title,a.url,a.digest,a.thumbmedia from media a inner join (select id from media  where title like "%` + prefix + `%"  and mediatype = "video" order by rand() limit 1) b on a.id=b.id; ` //20200330优化随机返回结果
				case "A", "a":
					sqlstr = `select a.mediatype,a.mediaid,a.title,a.url,a.digest,a.thumbmedia from media a inner join (select id from media  where title like "%` + prefix + `%"  and mediatype = "news" order by rand() limit 1) b on a.id=b.id; ` //20200330优化随机返回结果
				case "I", "i":
					sqlstr = `select a.mediatype,a.mediaid,a.title,a.url,a.digest,a.thumbmedia from media a inner join (select id from media  where title like "%` + prefix + `%"  and mediatype = "image" order by rand() limit 1) b on a.id=b.id; ` //20200330优化随机返回结果
				default:
					sqlstr = `select a.mediatype,a.mediaid,a.title,a.url,a.digest,a.thumbmedia from media a inner join (select id from media  where title like "%` + keyword + `%"  order by rand() limit 1) b on a.id=b.id; ` //20200330优化随机返回结果

				}

			} else {
				sqlstr = `select a.mediatype,a.mediaid,a.title,a.url,a.digest,a.thumbmedia from media  a inner join (select id from media  where title like "%` + keyword + `%"  order by rand() limit 1) b on a.id=b.id; ` //20200330优化随机返回结果

			}
		}
	}
	if querytype == "poem" {
		keyword = strings.ReplaceAll(keyword, ` `, `%" and content like "%`)
		sqlstr = `select a.content from poem  a inner join (select id from poem  where content like "%` + keyword + `%"  order by rand() limit 1) b on a.id=b.id; `
	}
	log.Println(sqlstr)

	row, err := db.Query(sqlstr)
	defer row.Close()
	if err != nil {
		log.Println("wechat-index error:", err)
		writefailed(w, r)
		return
	}

	if err = row.Err(); err != nil {
		log.Println("wechat-index error:", err)
		writefailed(w, r)
		return
	}

	count := 0
	for row.Next() {
		if querytype == "default" {
			if err := row.Scan(&message.Mediatype, &message.Mediaid, &message.Mediatitle, &message.Mediaurl, &message.Mediadigest, &message.Mediathumb); err != nil {
				log.Println("wechat-index error:", err)
				writefailed(w, r)
				return
			}
		}
		if querytype == "poem" {
			if err := row.Scan(&message.Mediadigest); err != nil {
				log.Println("wechat-index error:", err)
				writefailed(w, r)
				return
			}
			message.Mediatype = "poem"

		}
		count += 1
		message.Status = "success"
	}

	if count == 0 {
		message.Status = "failed"
		writefailed(w, r)
		return
	}

	if message.Mediatype == "news" { //图文类型时把封面图片的mediaid转换为Picurl
		sqlstr := `select url from media where mediaid = "` + message.Mediathumb + `"; `
		rows, _ := db.Query(sqlstr)
		defer rows.Close()
		for rows.Next() {
			rows.Scan(&message.Mediathumb)
		}
	}

	w.WriteHeader(http.StatusOK)
	js, _ := json.Marshal(message)
	w.Write(js)
	return
}
