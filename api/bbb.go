package handler

import (
	"archive/zip"
	"bufio"
	"bytes"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gen2brain/go-unarr"
)

type Apnmaininfo struct {
	//	Apnname        string
	Pgw            string //to support batch decode
	Vrf            string
	Ippool         string
	Ipallocatemode string
	Authmode       string
	Tunneltype     string
	Chargeonline   string
	Dpitemplte     string
	Pdns           string
	Sdns           string
	Pdnsv6         string
	Sdnsv6         string
	Radiuscharging string
	Aaaprofile     string
	Attrpriority   string
	L2tpinfo       string
	Pppauthchap    string
	Pppauthpap     string
	Pppregen       string
	Pppoption      string
	Typeofapn      string
	Svclassmap     string
}

type Tunnelinfo struct {
	Tunnelname    string
	Vrf           string
	Ipaddress     string
	Ip2address    string //loopback接口第二地址
	Tunnelvrf     string
	Tunnelsip     string
	Tunneldip     string
	Isakmpprofile string
	Ipsecprofile  string
}

type Isakmpprofile struct {
	Keyset  string
	Matchid string
	Policy  string
}

type Ipsecprofile struct {
	Transformset string
	Salifetime   string
	Pfs          string
	Acl          string
}

type Ipv4poolinfo struct {
	Poolname string
	Poolmode string
	Vrf      string
	Segment  []string
}

type Sapnlistinfo struct {
	Apnname string
	Key1    string
	Key2    string
}

type Ospfidinfo struct {
	Vrf     string
	Area    string
	Network []string
}

type Vrftunnelinfo struct {
	Interface []string
	Sip       []string
	Dip       []string
	Vrfoftun  []string
}

type Dpil34filterinfo struct {
	Iptype   string
	Apptype  string
	Serverip string
	Sdomain  string
	Ssport   string
	Seport   string
	Tranp    string
}

type Dpirule struct {
	L34filterg string
	L7filterg  string
	rulebase   string
}

type Dpitemplate struct {
	Name         string
	Drulebaseid  string
	Abrulebaseid string
	Rulebinding  []string
	Svclassmap   string
}

type Pccccr struct { //计费控制规则
	Type       string
	Name       string
	Rulebaseid string
	Chargerule string
	Action     string
}
type Pccccgr struct { //计费控制组规则
	Type     string
	Name     string
	Localccr string
}

type Rulebasetemplate struct {
	Name        string
	Ccr         []Pccccr
	Ccgr        []Pccccgr
	Svclassmap  string
	Dpitemplate string
}

type Numofapndecode struct {
	numgre    int
	numl2tp   int
	numipsec  int
	numassign int
	numradius int
	numdpi    int
	numerror  int
	common    int
	zhuan     int
	napn      int
}

type targetapn struct {
	apnname     string
	apntype     string
	pgwname     string
	sidlist     []string
	dpitemplate string
}

func makenowstring() (str string) {
	now := time.Now()
	h, m, s := now.Clock()
	return (strconv.Itoa(h) + ":" + strconv.Itoa(m) + ":" + strconv.Itoa(s))
}

func dpitmll347tostr(dpitml Dpitemplate, dpidomaininfo map[string]string, dpil7info map[string]string, dpiruleinfo map[string][]Dpirule, dpil34ginfo map[string][]string, dpil34info map[string]Dpil34filterinfo, dpil7ginfo map[string][]string, targetapninfo targetapn) (domain string, l34 string, l34g string, l7 string, l7g string, ff string) {
	adddomain, addl34, addl34g, addl7, addl7g, addff := "", "", "", "", "", ""

	for _, rulename := range dpitml.Rulebinding {
		for _, rule := range dpiruleinfo[rulename] {
			rulebaseid := rule.rulebase
			//	upforder += "<p><span>//以下为业务ID:" + rulebaseid + "的UPF L34/L7的过滤器、过滤器组和流过滤器的转换脚本：</span>"
			for _, l34name := range dpil34ginfo[rule.L34filterg] { //遍历三层过滤组
				l34filter := dpil34info[l34name]
				if l34filter.Sdomain != "" {
					if !strings.Contains(adddomain, (`ADD DOMAIN</code>:NAME="` + l34filter.Sdomain)) { //已增加的域名不重复增加
						adddomain += `<span><code class="note">ADD DOMAIN</code>:NAME="`
						adddomain += l34filter.Sdomain
						adddomain += `",DOMAINVALUE="<code class="key_word">`
						adddomain += dpidomaininfo[l34filter.Sdomain]
						adddomain += `</code>",DOMAINTYPE="DEFAULT";</span>`
					}
				}
				addl34 += `<span><code class="united">ADD L34FILTER</code>:FILTERNAME="L34-WLW-`
				addl34 += l34name
				addl34 += `",IPTYPE="<code class="string">`
				addl34 += l34filter.Iptype
				addl34 += `</code>",`
				if l34filter.Sdomain != "" {
					addl34 += `DOMAIN="`
					addl34 += l34filter.Sdomain
					addl34 += `",`
				} else {
					if l34filter.Iptype == "ipv4" {
						sip := l34filter.Serverip
						sip = strings.Replace(sip, "/", " ", 1)
						sipinfo := strings.Fields(sip)
						if len(sipinfo) == 2 {
							addl34 += `IPV4SERVERIP="<code class="string">`
							addl34 += sipinfo[0]
							addl34 += `</code>",IPV4SERVERIPMASK=<code class="value">`
							addl34 += sipinfo[1]
							addl34 += `</code>,`
						}
					} //ipv6不配置
				}
				addl34 += `PROTOCOL="<code class="class_name">`
				addl34 += l34filter.Tranp
				addl34 += `</code>",SERVERPORTSTART=`
				addl34 += l34filter.Ssport
				addl34 += `,SERVERPORTEND=`
				addl34 += l34filter.Seport
				addl34 += `;</span>`
				addl34g += `<span><code class="attribute">ADD L34FILTERGROUP</code>:GROUPNAME="L34G-WLW-` //UPF上L34过滤组用一个名称
				addl34g += (rulebaseid + `",L34FILTERNAME="L34-WLW-`)
				addl34g += l34name
				addl34g += `";</span>`

			}
			for _, l7name := range dpil7ginfo[rule.L7filterg] { //遍历七层过滤组
				l7filter := dpil7info[l7name]
				addl7 += `<span><code class="attribute">ADD L7FILTER</code>:FILTERNAME="L7-WLW-`
				addl7 += l7name
				addl7 += `",URL="<code class="united">`
				addl7 += l7filter
				addl7 += `</code>",METHOD="METHOD_ANY",APPTYPE="HTTP";</span>`
				addl7g += `<span><code class="created_function_name">ADD L7FILTERGROUP</code>:GROUPNAME="L7G-WLW-` //UPF上L7过滤组用一个名称
				addl7g += (rulebaseid + `",L7FILTERNAME="L7-WLW-`)
				addl7g += l7name
				addl7g += `";</span>`
			}
			//对每一个rulebaseid生成upf上的三层或七层流过滤器
			coml34str := (`ADD L34FILTERGROUP</code>:GROUPNAME="L34G-WLW-` + rulebaseid)
			coml7str := (`ADD L7FILTERGROUP</code>:GROUPNAME="L7G-WLW-` + rulebaseid)
			if strings.Contains(addl34g, coml34str) && !strings.Contains(addff, (`ADD FLOWFILTER</code>:FLOWFILTERNAME="FF-WLW-`+rulebaseid+`",L34FILTERGROUPNAME="L34G-WLW-`+rulebaseid)) { //重复的L34 filtergroup不用再次增加
				addff += `<span><code class="tag">ADD FLOWFILTER</code>:FLOWFILTERNAME="FF-WLW-`
				addff += (rulebaseid + `",L34FILTERGROUPNAME="L34G-WLW-` + rulebaseid + `";</span>`)
			}
			if strings.Contains(addl7, coml7str) && !strings.Contains(addff, (`ADD FLOWFILTER</code>:FLOWFILTERNAME="FF-WLW-`+rulebaseid+`",L7FILTERGROUPNAME="L7G-WLW-`+rulebaseid)) { //重复的L7 filtergroup不用再次增加 {
				addff += `<span><code class="tag">ADD FLOWFILTER</code>:FLOWFILTERNAME="FF-WLW-`
				addff += (rulebaseid + `",L7FILTERGROUPNAME="L7G-WLW-` + rulebaseid + `";</span>`)
			}
			//		upforder += `</p>`
		}
	}
	return adddomain, addl34, addl34g, addl7, addl7g, addff
}

func dpitmlpcctostr(dpitml Dpitemplate, dpiruleinfo map[string][]Dpirule, ccr []Pccccr, targetapninfo targetapn) (urrmap string, CHARG string, rule string, userprofile string, rulebindup string) {
	addurrmap, addcharg, addrule, adduserprofile, addrulebinup := "", "", "", "", ""

	rblist := map[string]bool{}
	for _, rulename := range dpitml.Rulebinding {
		for _, rule := range dpiruleinfo[rulename] {
			rulebaseid := rule.rulebase
			rblist[rulebaseid] = true
		}
	}
	rblist[dpitml.Drulebaseid] = true //默认业务ID需加入rblist中
	for rulebaseid, _ := range rblist {
		if len(rulebaseid) > 3 {
			addurrmap += (`<span><code class="string">ADD URRMAP</code>:URRID=` + rulebaseid[2:] + `1,TYPE="OFFLINECHARGESERVICE",SERVICEID=<code class="value">` + rulebaseid + `</code>,RATINGGROUP=` + rulebaseid + `,CHARGINGTYPE="INHERIT";</span>`)
			addurrmap += (`<span><code class="string">ADD URRMAP</code>:URRID=` + rulebaseid[2:] + `2,TYPE="N40ONLINECHARGESERVICE",SERVICEID=<code class="value">` + rulebaseid + `</code>,RATINGGROUP=` + rulebaseid + `,CHARGINGTYPE="INHERIT";</span>`)
			addcharg += (`<span><code class="tag">ADD CHARGINGDATA</code>:NAME="charge-rule` + rulebaseid + `",OFFLINEURRID=` + rulebaseid[2:] + `1,N40ONLINEURRID=` + rulebaseid[2:] + `2,FREE="false";</span>`)

		} else {
			addurrmap += "<span>//请注意核实以下业务ID是否是共有业务ID,UPF是否已经配置</span>"
			addurrmap += (`<span><code class="string">ADD URRMAP</code>:URRID=` + rulebaseid + `,TYPE="OFFLINECHARGESERVICE",SERVICEID=<code class="value">` + rulebaseid + `</code>,RATINGGROUP=` + rulebaseid + `,CHARGINGTYPE="INHERIT";</span><br>`)
			addcharg += (`<span><code class="tag">ADD CHARGINGDATA</code>:NAME="charge-rule` + rulebaseid + `",OFFLINEURRID=` + rulebaseid + `,FREE="false";</span>`)
		}

	}

	for _, v := range ccr {
		profiletype := ""
		_, ok := rblist[v.Rulebaseid]
		if ok || v.Rulebaseid == dpitml.Svclassmap { //冗余的预定义控制规则不转换
			if v.Rulebaseid == dpitml.Svclassmap { //100 service class map映射
				addrule += (`<span><code class="created_function_name">ADD RULE</code>:NAME="` + v.Name + `",FLOWFILTER="<code class="value">l34_ff_df</code>` + `",CHARGINGDATA="<code class="tag">` + v.Chargerule + `</code>",TRAFFICCONTROLDATA="<code class="tag">` + v.Action + `</code>";</span>`)
			} else {
				addrule += (`<span><code class="created_function_name">ADD RULE</code>:NAME="` + v.Name + `",FLOWFILTER="FF-WLW-` + v.Rulebaseid + `",CHARGINGDATA="<code class="tag">` + v.Chargerule + `</code>",TRAFFICCONTROLDATA="<code class="tag">` + v.Action + `</code>";</span>`)
			}
			if v.Type == "predefined" {
				profiletype = "PREDEFINED_RULE_GROUP"
			} else {
				profiletype = "LOCAL_RULE"
			}
			adduserprofile += (`<span><code class="class_name">ADD USERPROFILE</code>:NAME="` + v.Name + `",USERPROFILETYPE="<code class="created_function_name">` + profiletype + `</code>",DPIUPCONFIG="<code class="created_function_name">DPIConfig_NOurlrerecog</code>";</span>`)
			addrulebinup += (`<span><code class="key_word">ADD RULEBINDUP</code>:UPNAME="` + v.Name + `",RULENAME="` + v.Name + `";</span>`)
		}
	}
	return addurrmap, addcharg, addrule, adduserprofile, addrulebinup
}

func Handler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		w.Write([]byte(`<!DOCTYPE html>
		<html>
		<head><meta http-equiv="Content-Type" content="text/html" charset="utf-8">
		<title>中兴XGW配置文件解析和转换服务</title>
		<style type="text/css">
		html, body, div, span, applet, object, iframe,
h1, h2, h3, h4, h5, h6, p, blockquote, pre,
a, abbr, acronym, address, big, cite, code,
del, dfn, em, img, ins, kbd, q, s, samp,
small, strike, strong, sub, sup, tt, var,
b, u, i, center,
dl, dt, dd, ol, ul, li,
fieldset, form, label, legend,
table, caption, tbody, tfoot, thead, tr, th, td,
article, aside, canvas, details, embed,
figure, figcaption, footer, header, hgroup,
menu, nav, output, ruby, section, summary,
time, mark, audio, video {
  margin: 0;
  padding: 0;
  border: 0;
  font: inherit;
  font-size: 100%;
  vertical-align: baseline;
}

html {
  line-height: 1;
}

ol, ul {
  list-style: none;
}

table {
  border-collapse: collapse;
  border-spacing: 0;
}

caption, th, td {
  text-align: left;
  font-weight: normal;
  vertical-align: middle;
}

q, blockquote {
  quotes: none;
}
q:before, q:after, blockquote:before, blockquote:after {
  content: "";
  content: none;
}

a img {
  border: none;
}

article, aside, details, figcaption, figure, footer, header, hgroup, main, menu, nav, section, summary {
  display: block;
}

/***********VARIABLES***********/
/*Movement*/
/*Colors*/
/***********STYLES***********/
body {
  background-color: #d4e7ba;
}

/*.ele-container {
  background: -webkit-linear-gradient(top, rgba(0, 141, 210, 0.63) 0%, transparent 100%);
  background: linear-gradient(to bottom, rgba(0, 141, 210, 0.63) 0%, transparent 100%);
  height: 500px;
  overflow: hidden;
  position: relative;
  width: 100%;
}*/

.ele-wrapper {
  -webkit-animation: ele-movement 1s infinite linear;
          animation: ele-movement 1s infinite linear;
  left: 50%;
  position: absolute;
  top: 50%;
  -webkit-transform: translate3D(-50%, -75%, 0);
      -ms-transform: translate3D(-50%, -75%, 0);
          transform: translate3D(-50%, -75%, 0);
  width: 200px;
}

.ele-body {
  -webkit-animation: body-movement 1s infinite cubic-bezier(0.63, 0.15, 0.49, 0.93);
          animation: body-movement 1s infinite cubic-bezier(0.63, 0.15, 0.49, 0.93);
  background: -webkit-linear-gradient(top, #cfcfcf 0%, #9c9c9c 70%);
  background: linear-gradient(to bottom, #cfcfcf 0%, #9c9c9c 70%);
  border: 1px solid #808080;
  border-radius: 100px 50px 70px 60px;
  height: 165px;
  position: relative;
  width: 100%;
  z-index: 1;
}

.ele-tail {
  -webkit-animation: tail-movement 1s infinite cubic-bezier(0.63, 0.15, 0.49, 0.93);
          animation: tail-movement 1s infinite cubic-bezier(0.63, 0.15, 0.49, 0.93);
  border-top: 7px solid #808080;
  border-radius: 50%;
  height: 50px;
  position: absolute;
  -webkit-transform: translate3d(-3%, 69%, 0) rotateZ(-20deg);
          transform: translate3d(-3%, 69%, 0) rotateZ(-20deg);
  width: 64px;
}
.ele-tail:before {
  border-top: 5px solid #C2C2C2;
  border-radius: 50%;
  content: '';
  height: 50px;
  position: absolute;
  width: 64px;
  top: -6px;
}

.ele-head {
  -webkit-animation: head-movement 2s infinite linear;
          animation: head-movement 2s infinite linear;
  background: #C2C2C2;
  border-radius: 50%;
  border-top: 1px solid #808080;
  box-shadow: -1px 1px 2px #808080;
  height: 150px;
  position: absolute;
  -webkit-transform: translate3d(80%, -25%, 0);
          transform: translate3d(80%, -25%, 0);
  width: 155px;
}

.ele-eyes:before, .ele-eyes:after {
  -webkit-animation: eyes-blink 3.5s infinite linear;
          animation: eyes-blink 3.5s infinite linear;
  background-color: #FDFDFD;
  border-radius: 50%;
  bottom: -48px;
  content: '';
  height: 10px;
  position: absolute;
  width: 10px;
}

.ele-eyebrows {
  -webkit-animation: eyebrows-movement 1s infinite cubic-bezier(0.63, 0.15, 0.49, 0.93);
          animation: eyebrows-movement 1s infinite cubic-bezier(0.63, 0.15, 0.49, 0.93);
  background: -webkit-linear-gradient(bottom, #C2C2C2 20%, #9c9c9c 100%);
  background: linear-gradient(to top, #C2C2C2 20%, #9c9c9c 100%);
  border-radius: 10px;
  border-top: 1px solid #808080;
  bottom: 88px;
  height: 20px;
  left: 92px;
  position: absolute;
  width: 60px;
}

.ele-eyes {
  left: 60%;
  position: absolute;
  top: 6%;
}
.ele-eyes:before {
  left: 41px;
}
.ele-eyes:after {
  left: 10px;
}

.ele-ear {
  -webkit-animation: ear-movement 1s infinite linear;
          animation: ear-movement 1s infinite linear;
  background: -webkit-linear-gradient(right, #C2C2C2 10%, darkgray 100%);
  background: linear-gradient(to left, #C2C2C2 10%, darkgray 100%);
  border-bottom: 1px solid #808080;
  border-left: 1px solid #808080;
  border-top: 1px solid #808080;
  border-radius: 60px 0 0 50%;
  height: 110px;
  left: -22px;
  position: absolute;
  top: 25px;
  -webkit-transform: rotateZ(-10deg);
          transform: rotateZ(-10deg);
  width: 60px;
}

.ele-mouth {
  -webkit-animation: mouth-movement 1s infinite linear;
          animation: mouth-movement 1s infinite linear;
  background: -webkit-linear-gradient(top, #C2C2C2 50%, darkgray 100%);
  background: linear-gradient(to bottom, #C2C2C2 50%, darkgray 100%);
  border-radius: 0px 100% 0px 0px;
  border-top: 2px solid #808080;
  height: 160px;
  left: 83%;
  position: absolute;
  top: 35%;
  width: 30px;
}
.ele-mouth:before {
  -webkit-animation: mouth-after-movement 1s infinite linear;
          animation: mouth-after-movement 1s infinite linear;
  background-color: darkgray;
  border-bottom: 1px solid #808080;
  border-left: 1px solid #808080;
  border-radius: 8px;
  bottom: 0;
  content: '';
  height: 15px;
  left: -5px;
  position: absolute;
  width: 40px;
}

.ele-fang-front, .ele-fang-back {
  border-bottom: 12px solid #FFF;
  border-radius: 50%;
  height: 40px;
  position: absolute;
  -webkit-transform: rotateZ(20deg);
          transform: rotateZ(20deg);
  width: 50px;
}

.ele-fang-front {
  box-shadow: 0px 1px 0px #808080;
  left: 100px;
  top: 100px;
}
.ele-fang-front:before {
  background-color: #C2C2C2;
  bottom: -10px;
  content: '';
  height: 45px;
  left: -5px;
  position: absolute;
  width: 15px;
}
.ele-fang-front:after {
  background-color: #C2C2C2;
  border-radius: 0 50% 50% 0;
  bottom: -14px;
  box-shadow: 1px 1px 0px #808080;
  content: '';
  height: 21px;
  left: 6px;
  position: absolute;
  -webkit-transform: rotateZ(20deg);
          transform: rotateZ(20deg);
  width: 15px;
}

.ele-fang-back {
  border-bottom-color: #e6e6e6;
  left: 115px;
  top: 95px;
  z-index: -1;
}
.ele-fang-back:before {
  background-color: #C2C2C2;
  bottom: -10px;
  content: '';
  height: 25px;
  position: absolute;
  width: 30px;
}

div[class^="ele-leg-"] {
  border-left: 1px solid #808080;
  height: 88px;
  position: absolute;
  width: 50px;
}
div[class^="ele-leg-"]:before {
  background-color: rgba(74, 74, 74, 0.53);
  border-radius: 50%;
  bottom: -30px;
  box-shadow: 0 0 2px rgba(74, 74, 74, 0.53);
  content: '';
  height: 10px;
  left: 50%;
  position: absolute;
  -webkit-transform: translateX(-50%) rotateZ(0deg);
          transform: translateX(-50%) rotateZ(0deg);
  width: 50px;
}

.ele-leg-front {
  background-color: #9c9c9c;
  top: 100%;
  z-index: 1;
}
.ele-leg-front .ele-foot {
  background-color: #9c9c9c;
}

.ele-leg-back {
  background-color: #828282;
  top: 95%;
}
.ele-leg-back .ele-foot {
  background-color: #828282;
}
.ele-leg-back .ele-foot:before, .ele-leg-back .ele-foot:after {
  background-color: #bababa;
}

.ele-leg-1 {
  -webkit-animation: leg-animation 2s infinite cubic-bezier(0.63, 0.15, 0.49, 0.93) 0s;
          animation: leg-animation 2s infinite cubic-bezier(0.63, 0.15, 0.49, 0.93) 0s;
  right: 57.5%;
}
.ele-leg-1:before {
  -webkit-animation: foot-shadow-animation 2s infinite cubic-bezier(0.63, 0.15, 0.49, 0.93) 0s;
          animation: foot-shadow-animation 2s infinite cubic-bezier(0.63, 0.15, 0.49, 0.93) 0s;
}
.ele-leg-1 .ele-foot {
  -webkit-animation: foot-animation 2s infinite cubic-bezier(0.63, 0.15, 0.49, 0.93) 0s;
          animation: foot-animation 2s infinite cubic-bezier(0.63, 0.15, 0.49, 0.93) 0s;
}

.ele-leg-2 {
  -webkit-animation: leg-animation 2s infinite cubic-bezier(0.63, 0.15, 0.49, 0.93) -1s;
          animation: leg-animation 2s infinite cubic-bezier(0.63, 0.15, 0.49, 0.93) -1s;
  right: 67.5%;
}
.ele-leg-2:before {
  -webkit-animation: foot-shadow-animation 2s infinite cubic-bezier(0.63, 0.15, 0.49, 0.93) -1s;
          animation: foot-shadow-animation 2s infinite cubic-bezier(0.63, 0.15, 0.49, 0.93) -1s;
}
.ele-leg-2 .ele-foot {
  -webkit-animation: foot-animation 2s infinite cubic-bezier(0.63, 0.15, 0.49, 0.93) -1s;
          animation: foot-animation 2s infinite cubic-bezier(0.63, 0.15, 0.49, 0.93) -1s;
}

.ele-leg-3 {
  -webkit-animation: leg-animation 2s infinite cubic-bezier(0.63, 0.15, 0.49, 0.93) -1s;
          animation: leg-animation 2s infinite cubic-bezier(0.63, 0.15, 0.49, 0.93) -1s;
  right: 5%;
}
.ele-leg-3:before {
  -webkit-animation: foot-shadow-animation 2s infinite cubic-bezier(0.63, 0.15, 0.49, 0.93) -1s;
          animation: foot-shadow-animation 2s infinite cubic-bezier(0.63, 0.15, 0.49, 0.93) -1s;
}
.ele-leg-3 .ele-foot {
  -webkit-animation: foot-animation 2s infinite cubic-bezier(0.63, 0.15, 0.49, 0.93) -1s;
          animation: foot-animation 2s infinite cubic-bezier(0.63, 0.15, 0.49, 0.93) -1s;
}

.ele-leg-4 {
  -webkit-animation: leg-animation 2s infinite cubic-bezier(0.63, 0.15, 0.49, 0.93) 0s;
          animation: leg-animation 2s infinite cubic-bezier(0.63, 0.15, 0.49, 0.93) 0s;
  right: 15%;
}
.ele-leg-4:before {
  -webkit-animation: foot-shadow-animation 2s infinite cubic-bezier(0.63, 0.15, 0.49, 0.93) 0s;
          animation: foot-shadow-animation 2s infinite cubic-bezier(0.63, 0.15, 0.49, 0.93) 0s;
}
.ele-leg-4 .ele-foot {
  -webkit-animation: foot-animation 2s infinite cubic-bezier(0.63, 0.15, 0.49, 0.93) 0s;
          animation: foot-animation 2s infinite cubic-bezier(0.63, 0.15, 0.49, 0.93) 0s;
}

.ele-foot:before, .ele-foot:after {
  background-color: #E0E0E0;
  border-radius: 10px 10px 0 0;
  bottom: 0;
  content: '';
  height: 15px;
  position: absolute;
  width: 11px;
}

.ele-foot {
  border-radius: 25px 25px 35% 40%;
  bottom: -17.5px;
  box-shadow: -1px 1px 0px #808080;
  height: 35px;
  left: 50%;
  overflow: hidden;
  position: absolute;
  -webkit-transform: translateX(-49%) rotateZ(0deg);
          transform: translateX(-49%) rotateZ(0deg);
  width: 55px;
}
.ele-foot:before {
  right: -7.5px;
}
.ele-foot:after {
  bottom: -3px;
  right: 5px;
}

@-webkit-keyframes leg-animation {
  0% {
    height: 65px;
    -webkit-transform: translate3d(0, -90%, 0) rotate3d(0, 0, 1, 10deg) translate3d(0, 30%, 0);
            transform: translate3d(0, -90%, 0) rotate3d(0, 0, 1, 10deg) translate3d(0, 30%, 0);
  }
  25% {
    height: 40px;
  }
  50% {
    height: 65px;
    -webkit-transform: translate3d(0, -90%, 0) rotate3d(0, 0, 1, -15deg) translate3d(0, 30%, 0);
            transform: translate3d(0, -90%, 0) rotate3d(0, 0, 1, -15deg) translate3d(0, 30%, 0);
  }
  75% {
    height: 65px;
  }
  100% {
    height: 65px;
    -webkit-transform: translate3d(0, -90%, 0) rotate3d(0, 0, 1, 10deg) translate3d(0, 30%, 0);
            transform: translate3d(0, -90%, 0) rotate3d(0, 0, 1, 10deg) translate3d(0, 30%, 0);
  }
}

@keyframes leg-animation {
  0% {
    height: 65px;
    -webkit-transform: translate3d(0, -90%, 0) rotate3d(0, 0, 1, 10deg) translate3d(0, 30%, 0);
            transform: translate3d(0, -90%, 0) rotate3d(0, 0, 1, 10deg) translate3d(0, 30%, 0);
  }
  25% {
    height: 40px;
  }
  50% {
    height: 65px;
    -webkit-transform: translate3d(0, -90%, 0) rotate3d(0, 0, 1, -15deg) translate3d(0, 30%, 0);
            transform: translate3d(0, -90%, 0) rotate3d(0, 0, 1, -15deg) translate3d(0, 30%, 0);
  }
  75% {
    height: 65px;
  }
  100% {
    height: 65px;
    -webkit-transform: translate3d(0, -90%, 0) rotate3d(0, 0, 1, 10deg) translate3d(0, 30%, 0);
            transform: translate3d(0, -90%, 0) rotate3d(0, 0, 1, 10deg) translate3d(0, 30%, 0);
  }
}
@-webkit-keyframes foot-animation {
  0% {
    -webkit-transform: translateX(-49%) rotateZ(-10deg);
            transform: translateX(-49%) rotateZ(-10deg);
  }
  15% {
    -webkit-transform: translateX(-49%) rotateZ(5deg);
            transform: translateX(-49%) rotateZ(5deg);
  }
  40% {
    -webkit-transform: translateX(-49%) rotateZ(0deg);
            transform: translateX(-49%) rotateZ(0deg);
  }
  50% {
    -webkit-transform: translateX(-49%) rotateZ(15deg);
            transform: translateX(-49%) rotateZ(15deg);
  }
  100% {
    -webkit-transform: translateX(-49%) rotateZ(-10deg);
            transform: translateX(-49%) rotateZ(-10deg);
  }
}
@keyframes foot-animation {
  0% {
    -webkit-transform: translateX(-49%) rotateZ(-10deg);
            transform: translateX(-49%) rotateZ(-10deg);
  }
  15% {
    -webkit-transform: translateX(-49%) rotateZ(5deg);
            transform: translateX(-49%) rotateZ(5deg);
  }
  40% {
    -webkit-transform: translateX(-49%) rotateZ(0deg);
            transform: translateX(-49%) rotateZ(0deg);
  }
  50% {
    -webkit-transform: translateX(-49%) rotateZ(15deg);
            transform: translateX(-49%) rotateZ(15deg);
  }
  100% {
    -webkit-transform: translateX(-49%) rotateZ(-10deg);
            transform: translateX(-49%) rotateZ(-10deg);
  }
}
@-webkit-keyframes foot-shadow-animation {
  0% {
    -webkit-transform: translateX(-50%) rotateZ(-8deg);
            transform: translateX(-50%) rotateZ(-8deg);
    bottom: -20px;
    width: 50px;
  }
  25% {
    bottom: -30px;
    width: 40px;
  }
  50% {
    -webkit-transform: translateX(-50%) rotateZ(13deg);
            transform: translateX(-50%) rotateZ(13deg);
    bottom: -20px;
    width: 50px;
  }
  100% {
    -webkit-transform: translateX(-50%) rotateZ(-8deg);
            transform: translateX(-50%) rotateZ(-8deg);
    bottom: -20px;
    width: 50px;
  }
}
@keyframes foot-shadow-animation {
  0% {
    -webkit-transform: translateX(-50%) rotateZ(-8deg);
            transform: translateX(-50%) rotateZ(-8deg);
    bottom: -20px;
    width: 50px;
  }
  25% {
    bottom: -30px;
    width: 40px;
  }
  50% {
    -webkit-transform: translateX(-50%) rotateZ(13deg);
            transform: translateX(-50%) rotateZ(13deg);
    bottom: -20px;
    width: 50px;
  }
  100% {
    -webkit-transform: translateX(-50%) rotateZ(-8deg);
            transform: translateX(-50%) rotateZ(-8deg);
    bottom: -20px;
    width: 50px;
  }
}
@-webkit-keyframes eyes-blink {
  0% {
    height: 10px;
  }
  3% {
    height: 1px;
  }
  5% {
    height: 10px;
  }
  100% {
    height: 10px;
  }
}
@keyframes eyes-blink {
  0% {
    height: 10px;
  }
  3% {
    height: 1px;
  }
  5% {
    height: 10px;
  }
  100% {
    height: 10px;
  }
}
@-webkit-keyframes ele-movement {
  0% {
    -webkit-transform: translate3D(-50%, -54%, 0);
            transform: translate3D(-50%, -54%, 0);
  }
  50% {
    -webkit-transform: translate3D(-50%, -57%, 0);
            transform: translate3D(-50%, -57%, 0);
  }
  100% {
    -webkit-transform: translate3D(-50%, -54%, 0);
            transform: translate3D(-50%, -54%, 0);
  }
}
@keyframes ele-movement {
  0% {
    -webkit-transform: translate3D(-50%, -54%, 0);
            transform: translate3D(-50%, -54%, 0);
  }
  50% {
    -webkit-transform: translate3D(-50%, -57%, 0);
            transform: translate3D(-50%, -57%, 0);
  }
  100% {
    -webkit-transform: translate3D(-50%, -54%, 0);
            transform: translate3D(-50%, -54%, 0);
  }
}
@-webkit-keyframes mouth-movement {
  0% {
    height: 160px;
    width: 28px;
  }
  50% {
    height: 150px;
    width: 30px;
  }
  100% {
    height: 160px;
    width: 28px;
  }
}
@keyframes mouth-movement {
  0% {
    height: 160px;
    width: 28px;
  }
  50% {
    height: 150px;
    width: 30px;
  }
  100% {
    height: 160px;
    width: 28px;
  }
}
@-webkit-keyframes mouth-after-movement {
  0% {
    width: 37px;
  }
  50% {
    width: 40px;
  }
  100% {
    width: 37px;
  }
}
@keyframes mouth-after-movement {
  0% {
    width: 37px;
  }
  50% {
    width: 40px;
  }
  100% {
    width: 37px;
  }
}
@-webkit-keyframes tail-movement {
  0% {
    -webkit-transform: translate3d(-3%, 69%, 0) rotateZ(-20deg);
            transform: translate3d(-3%, 69%, 0) rotateZ(-20deg);
  }
  50% {
    -webkit-transform: translate3d(-5%, 65%, 0) rotateZ(-18deg);
            transform: translate3d(-5%, 65%, 0) rotateZ(-18deg);
  }
  100% {
    -webkit-transform: translate3d(-3%, 69%, 0) rotateZ(-20deg);
            transform: translate3d(-3%, 69%, 0) rotateZ(-20deg);
  }
}
@keyframes tail-movement {
  0% {
    -webkit-transform: translate3d(-3%, 69%, 0) rotateZ(-20deg);
            transform: translate3d(-3%, 69%, 0) rotateZ(-20deg);
  }
  50% {
    -webkit-transform: translate3d(-5%, 65%, 0) rotateZ(-18deg);
            transform: translate3d(-5%, 65%, 0) rotateZ(-18deg);
  }
  100% {
    -webkit-transform: translate3d(-3%, 69%, 0) rotateZ(-20deg);
            transform: translate3d(-3%, 69%, 0) rotateZ(-20deg);
  }
}
@-webkit-keyframes head-movement {
  0% {
    -webkit-transform: translate3d(80%, -22%, 0) rotateZ(3deg);
            transform: translate3d(80%, -22%, 0) rotateZ(3deg);
  }
  25% {
    -webkit-transform: translate3d(80%, -22.5%, 0) rotateZ(0deg);
            transform: translate3d(80%, -22.5%, 0) rotateZ(0deg);
  }
  50% {
    -webkit-transform: translate3d(80%, -23%, 0) rotateZ(-3deg);
            transform: translate3d(80%, -23%, 0) rotateZ(-3deg);
  }
  75% {
    -webkit-transform: translate3d(80%, -22.5%, 0) rotateZ(0deg);
            transform: translate3d(80%, -22.5%, 0) rotateZ(0deg);
  }
  100% {
    -webkit-transform: translate3d(80%, -22%, 0) rotateZ(3deg);
            transform: translate3d(80%, -22%, 0) rotateZ(3deg);
  }
}
@keyframes head-movement {
  0% {
    -webkit-transform: translate3d(80%, -22%, 0) rotateZ(3deg);
            transform: translate3d(80%, -22%, 0) rotateZ(3deg);
  }
  25% {
    -webkit-transform: translate3d(80%, -22.5%, 0) rotateZ(0deg);
            transform: translate3d(80%, -22.5%, 0) rotateZ(0deg);
  }
  50% {
    -webkit-transform: translate3d(80%, -23%, 0) rotateZ(-3deg);
            transform: translate3d(80%, -23%, 0) rotateZ(-3deg);
  }
  75% {
    -webkit-transform: translate3d(80%, -22.5%, 0) rotateZ(0deg);
            transform: translate3d(80%, -22.5%, 0) rotateZ(0deg);
  }
  100% {
    -webkit-transform: translate3d(80%, -22%, 0) rotateZ(3deg);
            transform: translate3d(80%, -22%, 0) rotateZ(3deg);
  }
}
@-webkit-keyframes body-movement {
  0% {
    height: 160px;
    margin-top: 5px;
  }
  50% {
    height: 162.5px;
    margin-top: 2.5px;
  }
  100% {
    height: 160px;
    margin-top: 5px;
  }
}
@keyframes body-movement {
  0% {
    height: 160px;
    margin-top: 5px;
  }
  50% {
    height: 162.5px;
    margin-top: 2.5px;
  }
  100% {
    height: 160px;
    margin-top: 5px;
  }
}
@-webkit-keyframes ear-movement {
  0% {
    height: 115px;
  }
  50% {
    height: 110px;
  }
  100% {
    height: 115px;
  }
}
@keyframes ear-movement {
  0% {
    height: 115px;
  }
  50% {
    height: 110px;
  }
  100% {
    height: 115px;
  }
}
@-webkit-keyframes eyebrows-movement {
  0% {
    height: 18px;
  }
  50% {
    height: 20px;
  }
  100% {
    height: 18px;
  }
}
@keyframes eyebrows-movement {
  0% {
    height: 18px;
  }
  50% {
    height: 20px;
  }
  100% {
    height: 18px;
  }
}
       </style>
		</head>
		<body style="font-size:15px;font-family:Microsoft YaHei"><div style="width:1150px; height:auto; margin:0 auto;border: 1px dashed green;line-height:1.5em;"><p align="center"><font face="黑体 color="green" size="4">中兴XGW配置文件解析和UPF脚本转换服务</font></b></p>
		  <p>&nbsp;&nbsp;&nbsp;&nbsp;本服务（Powered by 朱俊青-杭州处）用于接收中兴传统XGW(V4)设备的配置备份文件后进行解析返回APN主要信息或生成在UPF上的PCC/DPI部署脚本。服务提供者承诺不对上传的文件进行持久化记录，接收文件后将文件内容临时保存在内存中进行解析、返回结果后立即清理内存。</p>
		  <hr><form action="./bbb" method ="POST" onsubmit="return uploadprotect()" enctype="multipart/form-data">请选择待上传解析的中兴XGW配置备份文件:
		  <ul style="list-style-type: square;font-size:14px;margin:0;padding:0; list-style-position: inside;"><li>支持单套XGW配置文件的文本格式，支持单套或多套XGW配置文件压缩成一个<font color="#FF0000">7z(或zip)文件（<b>建议压缩上传</b>）</font></li></li></ul>
		  如欲转换生成某APN在UPF的DPI/PCC部署脚本,请输入专用apn名称(如CMIOTGT.ZJ)或通用apn名称和业务编码列表(空格分隔,如cmiot 1221000630 1221000631)。
		  <input type="text" name="targetapn" minlength="5" maxlength="200"  style="width:400px;height:20px;font-size:15px">
		  <center><input type="file" name="file" style="width:400px;height:30px;font-size: 20px;background-color:yellow;" accept=".7z,.zip,.txt,.log"></center>
		  <center><button type="submit"  id="b1" style="width:400px;height:50px;font-size: 30px;color: #00FF00;background-color: #000000;cursor:pointer;box-shadow:5px 2px 5px black;">上传并帮我解析或转换</button></center>
		  </form>
		</div>
		<script>

  		function uploadprotect()
  		{
			if (document.querySelector("input[type=file]").files.length ==0 )
			{
				alert("请选择一个xgw备份压缩文件");
				return false
			}else
			{
  				document.getElementById("b1").disabled=true;
   				document.getElementById("b1").innerHTML= "文件上传中，请耐心等待..";
    			return true;
			}
  		}
  		</script>
		<div class="ele-container">
			<div class="ele-wrapper">
			  <div class="ele-tail"></div>
			  <div class="ele-body">
				<div class="ele-head">
				  <div class="ele-eyebrows"></div>
				  <div class="ele-eyes"></div>
				  <div class="ele-mouth"></div>
				  <div class="ele-fang-front"></div>
				  <div class="ele-fang-back"></div>
				  <div class="ele-ear"></div>
				</div>
			  </div>
			  <div class="ele-leg-1 ele-leg-back">
				<div class="ele-foot"></div>
			  </div>
			  <div class="ele-leg-2 ele-leg-front">
				<div class="ele-foot"></div>
			  </div>
			  <div class="ele-leg-3 ele-leg-back">
				<div class="ele-foot"></div>
			  </div>
			  <div class="ele-leg-4 ele-leg-front">
				<div class="ele-foot"></div>
			  </div>
			</div>
		  </div>
		</body></html>`))
	case "POST":
		log.Println(makenowstring() + " 开始接收上传的文件。")
		targetapninfo := targetapn{}
		err := r.ParseMultipartForm(100 * 1024 * 1024) // 100 MB is the maximum file size
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		target := r.PostFormValue("targetapn")
		if target != "" {
			target = strings.TrimSpace(target)
			info := strings.Fields(target)
			targetapninfo.apnname = info[0]
			if len(info) > 1 {
				info = info[1:]
				for _, v := range info {
					targetapninfo.sidlist = append(targetapninfo.sidlist, v)
				}
			}
		}

		file, handler, err := r.FormFile("file")

		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		defer file.Close()

		if !strings.HasSuffix(handler.Filename, ".txt") && !strings.HasSuffix(handler.Filename, ".log") && !strings.HasSuffix(handler.Filename, ".zip") && !strings.HasSuffix(handler.Filename, ".7z") {
			w.Write([]byte("支持的文件格式为txt、log、zip、7z文件，请检查您的上传文件名后缀。"))
			file.Close()
			handler = nil
			return
		}

		log.Println(makenowstring() + " 开始读取PGW配置备份文件：" + handler.Filename + " ....")
		var pgwname []string
		var allpgwsapns [](map[string]Apnmaininfo)              //所有pgw的apn名称和apn信息映射表
		allpgwvrftun := map[string](map[string]Vrftunnelinfo){} //所有pgw的apn名称和vrf-隧道信息映射表
		numapn := Numofapndecode{}

		dpidomaininfo := map[string]string{}        //dpi域名信息
		dpil34info := map[string]Dpil34filterinfo{} //dpi三层过滤器
		dpil7info := map[string]string{}            //dpi七层url信息，只提取url字段
		dpil34ginfo := map[string][]string{}        //dpi三层过滤组
		dpil7ginfo := map[string][]string{}         //dpi七层过滤组
		dpiruleinfo := map[string][]Dpirule{}       //dpi规则信息
		dpitemplateinfo := map[string]Dpitemplate{} //dpi模板信息
		//charge-rule 不采集，自动根据业务id生成
		pccrbtemplateinfo := map[string]Rulebasetemplate{} //通用apn的rulebase模板信息，里面定义了dpi模板信息和预定义计费控制规则（组）
		apnccrinfo := map[string][]Pccccr{}                //专用apn的计费控制信息
		apnpccbrteminfo := map[string][]string{}           //通用apn下关联的rulebase模板信息
		ruconnrutmlinfo := map[string]string{}             //pgw下规则和rulebase关联配置

		if strings.HasSuffix(handler.Filename, "7z") { //unarr解压zip文件有问题，所有分开处理
			buff, err := ioutil.ReadAll(file)
			a, err := unarr.NewArchiveFromMemory(buff)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			list, err := a.List()
			for _, v := range list {
				a.EntryFor(v)
				data, err := a.ReadAll()
				if err != nil {
					log.Println("error reading compress file:", err)
					continue
				}
				reader := bufio.NewScanner(bytes.NewReader(data))
				singlenumapn := Numofapndecode{}
				temp, singlepgwapninfo, singlepgwtunnelinfo, singlenumapn, ruconnrutml, dpidomain, dpil34, dpil7, dpil34g, dpil7g, dpirule, dpitemplate, pccrbtemplate, apnccr, apnpccbrtem := getapninfo(reader)
				dpidomaininfo = dpidomain
				dpil34info = dpil34
				dpil7info = dpil7
				dpil34ginfo = dpil34g
				dpil7ginfo = dpil7g
				dpiruleinfo = dpirule
				dpitemplateinfo = dpitemplate
				pccrbtemplateinfo = pccrbtemplate
				apnccrinfo = apnccr
				ruconnrutmlinfo = ruconnrutml
				apnpccbrteminfo = apnpccbrtem

				if temp != "" {
					pgwname = append(pgwname, temp)
				}
				if len(singlepgwapninfo) > 0 {
					allpgwsapns = append(allpgwsapns, singlepgwapninfo)
					_, ok := singlepgwapninfo[targetapninfo.apnname]
					if ok {
						targetapninfo.pgwname = temp
						targetapninfo.apntype = singlepgwapninfo[targetapninfo.apnname].Typeofapn
						targetapninfo.dpitemplate = singlepgwapninfo[targetapninfo.apnname].Dpitemplte
						teml := dpitemplateinfo[targetapninfo.dpitemplate]
						teml.Svclassmap = (singlepgwapninfo[targetapninfo.apnname]).Svclassmap
						dpitemplateinfo[targetapninfo.dpitemplate] = teml
					}
				}

				if len(singlepgwtunnelinfo) > 0 { //单个pgw的隧道名称和隧道信息映射表
					vrftun := map[string]Vrftunnelinfo{}
					for k, v := range singlepgwtunnelinfo {
						if strings.Contains(k, "tunnel") {
							tempvrftunnelinfo, ok := vrftun[v.Vrf]
							if ok {
								tempvrftunnelinfo.Interface = append(tempvrftunnelinfo.Interface, strings.Replace(v.Tunnelname, "interface ", "", 1))
								tempvrftunnelinfo.Dip = append(tempvrftunnelinfo.Dip, v.Tunneldip)
								tempvrftunnelinfo.Sip = append(tempvrftunnelinfo.Sip, v.Tunnelsip)
								tempvrftunnelinfo.Vrfoftun = append(tempvrftunnelinfo.Vrfoftun, v.Tunnelvrf)
								vrftun[v.Vrf] = tempvrftunnelinfo
							} else {
								var temp Vrftunnelinfo
								temp.Interface = append(temp.Interface, strings.Replace(v.Tunnelname, "interface ", "", 1))
								temp.Dip = append(temp.Dip, v.Tunneldip)
								temp.Sip = append(temp.Sip, v.Tunnelsip)
								temp.Vrfoftun = append(temp.Vrfoftun, v.Tunnelvrf)
								vrftun[v.Vrf] = temp
							}
						}
					}
					allpgwvrftun[temp] = vrftun

				}
				numapn.numgre += singlenumapn.numgre
				numapn.numl2tp += singlenumapn.numl2tp
				numapn.numipsec += singlenumapn.numipsec
				numapn.numassign += singlenumapn.numassign
				numapn.numradius += singlenumapn.numradius
				numapn.numdpi += singlenumapn.numdpi
				numapn.numerror += singlenumapn.numerror
				numapn.common += singlenumapn.common
				numapn.zhuan += singlenumapn.zhuan
				numapn.napn += len(singlepgwapninfo)
			}

		} else if strings.HasSuffix(handler.Filename, "zip") {
			var zipReader *zip.Reader
			var file2 io.ReadCloser
			var buf *bufio.Scanner
			buff := bytes.NewBuffer([]byte{})
			size, err := io.Copy(buff, file)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			reader := bytes.NewReader(buff.Bytes())
			zipReader, err = zip.NewReader(reader, size)
			if err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}

			for _, f := range zipReader.File {
				file2, err = f.Open()
				if err != nil {
					http.Error(w, err.Error(), http.StatusBadRequest)
					return
				}
				defer file2.Close()
				buf = bufio.NewScanner(file2)
				singlenumapn := Numofapndecode{}
				temp, singlepgwapninfo, singlepgwtunnelinfo, singlenumapn, ruconnrutml, dpidomain, dpil34, dpil7, dpil34g, dpil7g, dpirule, dpitemplate, pccrbtemplate, apnccr, apnpccbrtem := getapninfo(buf)
				dpidomaininfo = dpidomain
				dpil34info = dpil34
				dpil7info = dpil7
				dpil34ginfo = dpil34g
				dpil7ginfo = dpil7g
				dpiruleinfo = dpirule
				dpitemplateinfo = dpitemplate
				pccrbtemplateinfo = pccrbtemplate
				apnccrinfo = apnccr
				ruconnrutmlinfo = ruconnrutml
				apnpccbrteminfo = apnpccbrtem

				if temp != "" {
					pgwname = append(pgwname, temp)
				}
				if len(singlepgwapninfo) > 0 {
					allpgwsapns = append(allpgwsapns, singlepgwapninfo)
					_, ok := singlepgwapninfo[targetapninfo.apnname]
					if ok {
						targetapninfo.pgwname = temp
						targetapninfo.apntype = singlepgwapninfo[targetapninfo.apnname].Typeofapn
						targetapninfo.dpitemplate = singlepgwapninfo[targetapninfo.apnname].Dpitemplte
						teml := dpitemplateinfo[targetapninfo.dpitemplate]
						teml.Svclassmap = (singlepgwapninfo[targetapninfo.apnname]).Svclassmap
						dpitemplateinfo[targetapninfo.dpitemplate] = teml
					}
				}

				if len(singlepgwtunnelinfo) > 0 { //单个pgw的隧道名称和隧道信息映射表
					vrftun := map[string]Vrftunnelinfo{}
					for k, v := range singlepgwtunnelinfo {
						if strings.Contains(k, "tunnel") {
							tempvrftunnelinfo, ok := vrftun[v.Vrf]
							if ok {
								tempvrftunnelinfo.Interface = append(tempvrftunnelinfo.Interface, strings.Replace(v.Tunnelname, "interface ", "", 1))
								tempvrftunnelinfo.Dip = append(tempvrftunnelinfo.Dip, v.Tunneldip)
								tempvrftunnelinfo.Sip = append(tempvrftunnelinfo.Sip, v.Tunnelsip)
								tempvrftunnelinfo.Vrfoftun = append(tempvrftunnelinfo.Vrfoftun, v.Tunnelvrf)
								vrftun[v.Vrf] = tempvrftunnelinfo
							} else {
								var temp Vrftunnelinfo
								temp.Interface = append(temp.Interface, strings.Replace(v.Tunnelname, "interface ", "", 1))
								temp.Dip = append(temp.Dip, v.Tunneldip)
								temp.Sip = append(temp.Sip, v.Tunnelsip)
								temp.Vrfoftun = append(temp.Vrfoftun, v.Tunnelvrf)
								vrftun[v.Vrf] = temp
							}
						}
					}
					allpgwvrftun[temp] = vrftun
				}
				numapn.numgre += singlenumapn.numgre
				numapn.numl2tp += singlenumapn.numl2tp
				numapn.numipsec += singlenumapn.numipsec
				numapn.numassign += singlenumapn.numassign
				numapn.numradius += singlenumapn.numradius
				numapn.numdpi += singlenumapn.numdpi
				numapn.numerror += singlenumapn.numerror
				numapn.common += singlenumapn.common
				numapn.zhuan += singlenumapn.zhuan
				numapn.napn += len(singlepgwapninfo)
			}

		} else {
			buf := bufio.NewScanner(file)
			singlenumapn := Numofapndecode{}
			//dpidomaininfo, dpil34info, dpil7info, dpil34ginfo, dpil7ginfo, dpiruleinfo, dpitemplateinfo, pccrbtemplateinfo, apnccrinfo, apnpccbrteminfo
			temp, singlepgwapninfo, singlepgwtunnelinfo, singlenumapn, ruconnrutml, dpidomain, dpil34, dpil7, dpil34g, dpil7g, dpirule, dpitemplate, pccrbtemplate, apnccr, apnpccbrtem := getapninfo(buf)
			dpidomaininfo = dpidomain
			dpil34info = dpil34
			dpil7info = dpil7
			dpil34ginfo = dpil34g
			dpil7ginfo = dpil7g
			dpiruleinfo = dpirule
			dpitemplateinfo = dpitemplate
			pccrbtemplateinfo = pccrbtemplate
			apnccrinfo = apnccr
			ruconnrutmlinfo = ruconnrutml
			apnpccbrteminfo = apnpccbrtem
			if temp != "" {
				pgwname = append(pgwname, temp)
			}
			if len(singlepgwapninfo) > 0 {
				allpgwsapns = append(allpgwsapns, singlepgwapninfo)
				_, ok := singlepgwapninfo[targetapninfo.apnname]
				if ok {
					targetapninfo.pgwname = temp
					targetapninfo.apntype = singlepgwapninfo[targetapninfo.apnname].Typeofapn
					targetapninfo.dpitemplate = singlepgwapninfo[targetapninfo.apnname].Dpitemplte
					teml := dpitemplateinfo[targetapninfo.dpitemplate]
					teml.Svclassmap = (singlepgwapninfo[targetapninfo.apnname]).Svclassmap
					dpitemplateinfo[targetapninfo.dpitemplate] = teml
				}
			}

			if len(singlepgwtunnelinfo) > 0 { //单个pgw的隧道名称和隧道信息映射表
				var vrftun map[string]Vrftunnelinfo
				for k, v := range singlepgwtunnelinfo {
					if strings.Contains(k, "tunnel") {
						tempvrftunnelinfo := vrftun[v.Vrf]
						tempvrftunnelinfo.Interface = append(tempvrftunnelinfo.Interface, strings.Replace(v.Tunnelname, "interface ", "", 1))
						tempvrftunnelinfo.Dip = append(tempvrftunnelinfo.Dip, v.Tunneldip)
						tempvrftunnelinfo.Sip = append(tempvrftunnelinfo.Sip, v.Tunnelsip)
						tempvrftunnelinfo.Vrfoftun = append(tempvrftunnelinfo.Vrfoftun, v.Tunnelvrf)
						vrftun[v.Vrf] = tempvrftunnelinfo
					}
				}
				allpgwvrftun[temp] = vrftun

			}

			numapn.numgre += singlenumapn.numgre
			numapn.numl2tp += singlenumapn.numl2tp
			numapn.numipsec += singlenumapn.numipsec
			numapn.numassign += singlenumapn.numassign
			numapn.numradius += singlenumapn.numradius
			numapn.numdpi += singlenumapn.numdpi
			numapn.numerror += singlenumapn.numerror
			numapn.common += singlenumapn.common
			numapn.zhuan += singlenumapn.zhuan
			numapn.napn += len(singlepgwapninfo)

		}

		file.Close()

		var pgwlist string

		for _, v := range pgwname {
			pgwlist += (v + " ")
		}
		pgwlist = strings.TrimSpace(pgwlist) //去掉最后的空格
		log.Println(makenowstring() + " 完成" + pgwlist + "配置文件读取和解析")

		if len(allpgwsapns) == 0 {
			w.Write([]byte("没有解析出任何APN信息，请核实上传文件的正确性。"))
			//		numapn = nil
			return
		}

		upforder := ""

		if targetapninfo.apnname != "" {
			if targetapninfo.pgwname == "" {
				w.Write([]byte("没有在PGW文件中找到" + targetapninfo.apnname + "的配置，请核实文件准确性后重新尝试。"))
				return
			}
			w.Write([]byte(`<html><head>
			<style type="text/css">
#code_block {
    background: #2d2d2d;
    color: rgb(201,209,217);
    font-family: Consolas;
    text-align: left;
    padding: 1em;
    padding-left: 0.8em;
    margin: 1em;
    border-radius: 5px;
    counter-reset: line;
    white-space: normal;
    word-spacing: normal;
    word-break: normal;
    word-wrap: normal;
    line-height: 1.5;
    width: calc(100% - 63px);
    overflow-x: auto;
}

#code_block code {
    font-family: Consolas;
}

#code_block .key_word,
#code_block .operator,
#code_block .united {
    color: rgb(255,123,114);
}
#code_block .value,
#code_block .default_function_name,
#code_block .attribute {
    color: rgb(121,192,255);
}
#code_block .note {
    color: rgb(139,148,158);
}
#code_block .created_function_name {
    color: rgb(210,168,255);
}
#code_block .class_name {
    color: rgb(247,162,87);
}
#code_block .string {
    color: rgb(165,214,255);
}
#code_block .tag {
    color: #7EE787;
}
#code_block .href_link {
    color: rgb(165,214,255);
    border-bottom: 2px solid rgb(165,214,255);
}

#code_block span {
    display: block;
    line-height: 1.5rem;
    white-space: pre;
}

#code_block span:before {
    counter-increment: line;
    content: counter(line);
    display: inline-block;
    width: 3em;
    text-align: right;
    border-right: 2px solid #999;
    padding-right: .8em;
    margin-right: 1em;
    color: #999;
}
button{
	display: inline-block;
	border-radius: 1px;
	background-color: #000000;
	border: none;
	color: #00FF00;
	text-align: center;
	font-size: 16px;
	padding: 1px;
	width: 180px;
	transition: all 0.5s;
	cursor: pointer;
	margin: 1px;
}
</style>
<script>
function Copyto() {
	var copyText = document.getElementById("code_block").innerText;
	navigator.clipboard.writeText(copyText);
}
</script>
			<meta charset="utf-8"></head>
			<body><a href='javascript:history.go(-1)'>返回</a>
			<button onclick="Copyto()" style="float:right">复制脚本到剪切板</button>`))
			upforder += `<pre id="code_block">`
			upforder += `<span>//以下根据` + targetapninfo.pgwname + `上的` + targetapninfo.apntype + `apn：` + targetapninfo.apnname + `在XGW上的相关配置，生成UPF上的DPI/PCC部署脚本:</span>`
			upforder += `<span>//转换逻辑1：APN按照APN下配置的DPI模板和转换为UPF的L3/4/7过滤器和流过滤器，按照apn下配置的计费控制规则转换为UPF的用户模板、计费规则、规则和绑定；</span>`
			upforder += `<span>//apn下如果rulebasemapping enable指示有rulebase模板，则同样进行流过滤器和用户模板、规则等转换；</span>`
			upforder += `<span>//转换逻辑2：通用APN+业务ID列表，遍历业务列表，按照业务ID映射的rulebase模板进行流过滤器和用户模板、规则等转换；</span>`
			upforder += `<span>//生成的转换脚本中的标识大部分使用xgw上的标识，L3/4/7过滤组名称加前缀L347-WLW-,流过滤器加前缀FF-WLW-</span>`
			upforder += `<span>//请注意核对脚本中的规则组名称，需要与SMF配置的本地名称和PCF下方的名称保持一致；</span>`
			upforder += `<span>//请注意核对脚本中的增加用户模板ADD USERPROFILE中的DPI模板（DPIUPCONFIG）与目标UPF已配置一致；</span>`
			upforder += `<span>//请注意核对脚本中的增加规则ADD RULE中的业务流控制策-放通或拦截（TRAFFICCONTROLDATA），默认取自XGW的控制策略名称，可修改为UPF已有策略或增加XGW的策略名称；</span>`
			upforder += `<span>//请注意核对脚本中的L34 L7过滤规则和规则组是否属于共用（如DNS信令规则）与现网重复，或者XGW本身存在冗余重复配置，转换程序可能都进行了转换，如重复则请自行删除；</span>`
			upforder += `<span>//请注意核对脚本中的默认流过滤器的名称需修改为与目标UPF上的名称保持一致，脚本默认使用“l34_ff_df”</span>`

			if targetapninfo.apntype == "专用" || (targetapninfo.apntype == "通用" && len(targetapninfo.sidlist) == 0) {
				if targetapninfo.dpitemplate == "disable" {
					w.Write([]byte("该专用apn未启用DPI，无需进行DPI/PCC配置。"))
					return
				}
				upforder += ("<span>//以下为xgw上apn:" + targetapninfo.apnname + "使用的DPI模板" + targetapninfo.dpitemplate + "相关的UPF转换脚本：</span><span>—————————————————————————————————————————————————————————————————————————</span>")
				dpitml := dpitemplateinfo[targetapninfo.dpitemplate]

				adddomain, addl34, addl34g, addl7, addl7g, addff := dpitmll347tostr(dpitml, dpidomaininfo, dpil7info, dpiruleinfo, dpil34ginfo, dpil34info, dpil7ginfo, targetapninfo)
				upforder += "<span>//以下为增加域名、L34/L7过滤器(组)、流过滤器脚本：</span>" + adddomain + addl34 + addl34g + addl7 + addl7g + addff
				addurrmap, addcharg, addrule, adduserprofile, addrulebinup := dpitmlpcctostr(dpitml, dpiruleinfo, apnccrinfo[targetapninfo.apnname], targetapninfo)
				upforder += "<span>//以下为增加计费、规则、用户模板、规则绑定脚本：</span>" + addurrmap + addcharg + addrule + adduserprofile + addrulebinup
				upforder += ("<span>//xgw上apn:" + targetapninfo.apnname + "使用的DPI模板" + targetapninfo.dpitemplate + "的UPF转换指令生成完毕。</span><span>—————————————————————————————————————————————————————————————————————————</span><br>")

				if len(apnpccbrteminfo[targetapninfo.apnname]) > 0 {
					for _, rbtmlname := range apnpccbrteminfo[targetapninfo.apnname] {
						rbtml, ok := pccrbtemplateinfo[rbtmlname]
						if ok {
							upforder += ("<span>//以下为在xgw的通用apn的rulebasemapping enable 指示的rulebase-template：" + rbtmlname + "相关的UPF转换脚本（请注意核实准确性）：</span><span>————————————————————————————————————————————————————————————————————</span><br>")
							//	dpitml := dpitemplateinfo[rbtml.Dpitemplate]

							tml := dpitemplateinfo[rbtml.Dpitemplate]
							upforder += ("<span>//以下为xgw上rulebase-template：" + rbtmlname + " 中指定的DPI模板：" + rbtml.Dpitemplate + "转换为L34/L7过滤器、过滤组、流过滤器的脚本：</span><p>")
							adddomain, addl34, addl34g, addl7, addl7g, addff := dpitmll347tostr(tml, dpidomaininfo, dpil7info, dpiruleinfo, dpil34ginfo, dpil34info, dpil7ginfo, targetapninfo)
							upforder += adddomain + addl34 + addl34g + addl7 + addl7g + addff

							upforder += ("<span>以下为xgw上rulebase-template：" + rbtmlname + "的预定义规则（组）-计费控制规则转换为新增规则、用户模板、规则绑定的脚本：</span><p>")

							if rbtml.Svclassmap != "" {
								tmptml := dpitemplateinfo[rbtml.Dpitemplate]
								tmptml.Svclassmap = rbtml.Svclassmap
								dpitemplateinfo[rbtml.Dpitemplate] = tmptml
							}
							addurrmap, addcharg, addrule, adduserprofile, addrulebinup := dpitmlpcctostr(tml, dpiruleinfo, rbtml.Ccr, targetapninfo)
							for _, v := range rbtml.Ccgr {
								if !strings.Contains(adduserprofile, (`ADD USERPROFILE</code>:NAME="` + v.Name)) { //防止重复增加xgw预定义组对应到upf的用户预定义模板
									adduserprofile += (`<span><code class="class_name">ADD USERPROFILE</code>:NAME="` + v.Name + `",USERPROFILETYPE="<code class="created_function_name">"PREDEFINED_RULE_GROUP"</code>",DPIUPCONFIG="<code class="created_function_name">DPIConfig_NOurlrerecog</code>";</span>`)
								}
								addrulebinup += (`<span><code class="key_word">ADD RULEBINDUP</code>:UPNAME="` + v.Name + `",RULENAME="` + v.Localccr + `";</span>`)
							}
							upforder += addurrmap + addcharg + addrule + adduserprofile + addrulebinup

						}
						upforder += ("<span>//xgw的通用apn的rulebasemapping enable 指示的rulebase-template：" + rbtmlname + "转换为UPF指令生成完毕。</span><span>————————————————————————————————————————————————————————————————————</span><br>")
					}
				}

			} else {
				for _, v := range targetapninfo.sidlist {
					rbtmlname := ruconnrutmlinfo[(v + "enable")]
					rbtmlnameg := ruconnrutmlinfo[(v + "enablegr")]
					if rbtmlname == "" && rbtmlnameg == "" {
						upforder += `<span>\\未在xgw配置中找到业务ID：` + v + `的配置信息，跳过</span>`
						continue
					}
					if rbtmlname == "" {
						rbtmlname = rbtmlnameg
					}
					rbtml, ok := pccrbtemplateinfo[rbtmlname]
					if !ok {
						upforder += `<span>\\未在xgw配置中找到rulebase模板：` + rbtmlname + `的配置信息，跳过</span>`
						continue
					}

					upforder += ("<span>//以下为xgw上rulebase-template：CMIOT_" + v + "相关的UPF转换脚本：</span><span>————————————————————————————————————————————————————————————————————</span><br>")
					tml := dpitemplateinfo[rbtml.Dpitemplate]
					upforder += ("<span>//以下为xgw上rulebase-template：CMIOT_" + v + " 中指定的DPI模板：" + rbtml.Dpitemplate + " 转换为L34/L7过滤器、过滤组、流过滤器的脚本：</span><p>")
					adddomain, addl34, addl34g, addl7, addl7g, addff := dpitmll347tostr(tml, dpidomaininfo, dpil7info, dpiruleinfo, dpil34ginfo, dpil34info, dpil7ginfo, targetapninfo)
					upforder += adddomain + addl34 + addl34g + addl7 + addl7g + addff

					upforder += ("<span>//以下为xgw上rulebase-template：CMIOT_" + v + "的预定义规则（组）-计费控制规则转换为新增规则、用户模板、规则绑定的脚本：</span><p>")

					if rbtml.Svclassmap != "" {
						tmptml := dpitemplateinfo[rbtml.Dpitemplate]
						tmptml.Svclassmap = rbtml.Svclassmap
						dpitemplateinfo[rbtml.Dpitemplate] = tmptml
					}
					addurrmap, addcharg, addrule, adduserprofile, addrulebinup := dpitmlpcctostr(tml, dpiruleinfo, rbtml.Ccr, targetapninfo)

					for _, v := range rbtml.Ccgr {
						if !strings.Contains(adduserprofile, (`ADD USERPROFILE</code>:NAME="` + v.Name)) { //防止重复增加xgw预定义组对应到upf的用户预定义模板
							adduserprofile += (`<span><code class="class_name">ADD USERPROFILE</code>:NAME="` + v.Name + `",USERPROFILETYPE="<code class="created_function_name">"PREDEFINED_RULE_GROUP"</code>",DPIUPCONFIG="<code class="created_function_name">DPIConfig_NOurlrerecog</code>";</span>`)
						}
						addrulebinup += (`<span><code class="key_word">ADD RULEBINDUP</code>:UPNAME="` + v.Name + `",RULENAME="` + v.Localccr + `";</span>`)
					}
					upforder += addurrmap + addcharg + addrule + adduserprofile + addrulebinup
					upforder += ("<span>//xgw上rulebase-template：CMIOT_" + v + "的转换脚本结束</span><span>————————————————————————————————————————————————————————————————————</span><br>")
				}
			}
			upforder += "</pre>"
			w.Write([]byte(upforder))
			w.Write([]byte(`</body></html>`))
			//释放内存
			upforder = ""
			dpidomaininfo = nil
			dpil34info = nil
			dpil7info = nil
			dpil34ginfo = nil
			dpil7ginfo = nil
			dpiruleinfo = nil
			dpitemplateinfo = nil
			pccrbtemplateinfo = nil
			apnccrinfo = nil
			ruconnrutmlinfo = nil
			apnpccbrteminfo = nil

			return

		}

		log.Println(makenowstring() + " 开始导出所有APN概要信息...")
		w.Write([]byte(`<html><head><meta charset="utf-8"><title>` +
			pgwlist +
			`s apninfo</title><script type="text/javascript" src="https://unpkg.com/xlsx@0.15.1/dist/xlsx.full.min.js"></script></head>
			<script>
					function ExportToExcel(type, fn, dl) {
							var elt = document.getElementById('apn_info');
							var wb = XLSX.utils.table_to_book(elt, { sheet: "apn" });
							return dl ?
								XLSX.write(wb, { bookType: type, bookSST: true, type: 'base64' }) :
								XLSX.writeFile(wb, fn || ('` + pgwlist + `_apn_info.' + (type || 'xlsx')));
							 }
			</script>
			<style type="text/css">
			a{
				text-decoration:none;
			}
			table {
				width: 100%;
				background: #ccc;
				margin: 10px auto;
				border-collapse: collapse;
				font-family:"Verdana", Times, serif;
			}
			th,
			td {
				height: 25px;
				line-height: 25px;
				text-align: center;
				border: 1px solid #ccc;
			}
			th {
				background: #eee;
				font-weight: normal;
			}
			tr {
				background: #fff;
			}
            td {
             font-size: 15px;
            }
		    tr:hover {
				background: #cc0;
			}
			td a {
				color: #06f;
				text-decoration: none;
			}
			td a:hover {
				color: #06f;
				text-decoration: underline;
			}
			button {
				display: inline-block;
				border-radius: 1px;
				background-color: #000000;
				border: none;
				color: #00FF00;
				text-align: center;
				font-size: 16px;
				padding: 1px;
				width: 180px;
				transition: all 0.5s;
				cursor: pointer;
				margin: 1px;
			  }
			</style><body><button onclick="ExportToExcel('xlsx')" style="float:right">结果另存为Excel...</button>
			<a href='javascript:history.go(-1)'>返回</a>
			<table id="apn_info"><thead><th colspan=`))
		if len(allpgwsapns) > 1 {
			w.Write([]byte(`14><b>` + pgwlist + `的APN信息概要表</b></th></thead><thead><th colspan=14`))
		} else {
			w.Write([]byte(`13><b>` + pgwlist + `的APN信息概要表</b></th></thead><thead><th colspan=13`))
		}

		w.Write([]byte(`>共部署` + strconv.Itoa(numapn.napn) + `个apn(专用apn` + strconv.Itoa(numapn.zhuan) + `,通用apn` + strconv.Itoa(numapn.common) + `个)，其中使用GRE隧道的有` + strconv.Itoa(numapn.numgre) + `个，使用IPSEC隧道的有` + strconv.Itoa(numapn.numipsec) + `个，使用L2TP隧道的有` + strconv.Itoa(numapn.numl2tp) + `个，开启内容计费的有` + strconv.Itoa(numapn.numdpi) + `个，静态地址分配的有` + strconv.Itoa(numapn.numassign) + `个，采用Radius鉴权的有` + strconv.Itoa(numapn.numradius) + `个。`))
		if numapn.numerror > 0 {
			w.Write([]byte(`<br><b><font color="red">共有` + strconv.Itoa(numapn.numerror) + `个APN没有关联VRF，疑似错误或者垃圾配置，请注意核实。</font></b>`))
		}
		if len(pgwname) == 1 {
			w.Write([]byte(`</th></thead><thead><th>APN</th><th>vrf</th><th>地址池</th><th>地址分配</th><th>鉴权</th><th>隧道类型</th><th>隧道名称</th><th>隧道底层VRF</th><th>隧道源地址</th><th>隧道目标地址</th>
			<th>DPI模板</th><th>PDNS</th><th>AAA模板</th></thead><tbody>`))
			//	w.Write([]byte([]string{"apn", "vrf", "ippool", "ippool-mode", "ip-allocate-mode", "authentication-mode", "tunneltype", "charge-online", "dpi-templte", "primary-dns", "primary-dns-v6", "secondary-dns", "secondary-dns-v6", "charge-redius", "aaa-profile"}))
			for _, singlepgwapninfo := range allpgwsapns {
				for k, value := range singlepgwapninfo {
					tunnelnames := ""
					dips := ""
					sips := ""
					vrfs := ""
					if value.Vrf != "" { //2023-08-1修改，apn不关联apn时不处理
						for _, v := range allpgwvrftun[value.Pgw][value.Vrf].Interface {
							tunnelnames += (v + "<br>")
						}
						for _, v := range allpgwvrftun[value.Pgw][value.Vrf].Dip {
							dips += (v + "<br>")
						}
						for _, v := range allpgwvrftun[value.Pgw][value.Vrf].Sip {
							sips += (v + "<br>")
						}
						for _, v := range allpgwvrftun[value.Pgw][value.Vrf].Vrfoftun {
							vrfs += (v + "<br>")
						}
					}
					if value.Tunneltype == "L2TP" {
						tempstrlist := strings.Fields(value.L2tpinfo)
						for k, v := range tempstrlist {
							if v == "lns-ip-address" {
								dips += (tempstrlist[k+1] + "<br>")
							}
							if v == "lac-ip-address" {
								sips += (tempstrlist[k+1] + "<br>")
								vrfs += (tempstrlist[k+3] + "<br>")
							}

						}
					}

					w.Write([]byte("<tr><td>" + k + "</td><td>" + value.Vrf + "</td><td>" + value.Ippool + "</td><td>" + value.Ipallocatemode + "</td><td>" + strings.Fields(value.Authmode)[0] + "</td><td>" + value.Tunneltype + "</td><td>" + tunnelnames + "</td><td>" + vrfs + "</td><td>" + sips + "</td><td>" + dips + "</td><td>(" + value.Typeofapn + ")" + value.Dpitemplte + "</td><td>" + value.Pdns + "</td><td>" + value.Aaaprofile + "</td></tr>"))
				}
			}
		} else {
			w.Write([]byte(`</th></thead><thead><th>PGW</th><th>APN</th><th>vrf</th><th>地址池</th><th>地址分配</th><th>鉴权</th><th>隧道类型</th><th>隧道名称</th><th>隧道底层VRF</th><th>隧道源地址</th><th>隧道目标地址</th>
			<th>DPI模板</th><th>PDNS</th><th>AAA模板</th></thead><tbody>`))
			for _, singlepgwapninfo := range allpgwsapns {
				for k, value := range singlepgwapninfo {
					tunnelnames := ""
					dips := ""
					sips := ""
					vrfs := ""
					if value.Vrf != "" { //2023-08-1修改，apn不关联apn时不处理
						for _, v := range allpgwvrftun[value.Pgw][value.Vrf].Interface {
							tunnelnames += (v + "<br>")
						}
						for _, v := range allpgwvrftun[value.Pgw][value.Vrf].Dip {
							dips += (v + "<br>")
						}
						for _, v := range allpgwvrftun[value.Pgw][value.Vrf].Sip {
							sips += (v + "<br>")
						}
						for _, v := range allpgwvrftun[value.Pgw][value.Vrf].Vrfoftun {
							vrfs += (v + "<br>")
						}
					}
					if value.Tunneltype == "L2TP" {
						tempstrlist := strings.Fields(value.L2tpinfo)
						for k, v := range tempstrlist {
							if v == "lns-ip-address" {
								dips += (tempstrlist[k+1] + "<br>")
							}
							if v == "lac-ip-address" {
								sips += (tempstrlist[k+1] + "<br>")
								vrfs += (tempstrlist[k+3] + "<br>")
							}
						}
					}
					w.Write([]byte("<tr><td>" + value.Pgw + "</td><td>" + k + "</td><td>" + value.Vrf + "</td><td>" + value.Ippool + "</td><td>" + value.Ipallocatemode + "</td><td>" + strings.Fields(value.Authmode)[0] + "</td><td>" + value.Tunneltype + "</td><td>" + tunnelnames + "</td><td>" + vrfs + "</td><td>" + sips + "</td><td>" + dips + "</td><td>(" + value.Typeofapn + ")" + value.Dpitemplte + "</td><td>" + value.Pdns + "</td><td>" + value.Aaaprofile + "</td></tr>"))
				}
			}

		}
		w.Write([]byte("</tbody></table></body></html>"))
		log.Println(makenowstring() + " 完成导出所有APN概要信息")
		//	numapn = nil
		allpgwsapns = nil

	default:
	}
	return
}

func getapninfo(buf *bufio.Scanner) (pgwn string, apninfo map[string]Apnmaininfo, tunnelsinfo map[string]Tunnelinfo, numapn Numofapndecode, ruconnrutml map[string]string, dpidomain map[string]string, dpil34 map[string]Dpil34filterinfo, dpil7 map[string]string, dpil34g map[string][]string, dpil7g map[string][]string, dpirule map[string][]Dpirule, dpitemplate map[string]Dpitemplate, pccrbtemplate map[string]Rulebasetemplate, apnccr map[string][]Pccccr, apnpccbrtem map[string][]string) {
	var allapns = make(map[string]Apnmaininfo) //apn名称和apn信息映射表
	var ngre, nl2tp, nipsec, nassign, nradius, ndpi, nerror, ncommon, nzhuan int
	apntag := false
	statictag := false
	interfacetag := false
	gretunneltag := false
	ipsectag := false
	ipv4pooltag := false
	ipv4acltag := false
	isakmptag := false
	ospfv2tag := false
	dpitag := false
	dpitmltag := false
	rbtmltag := false
	rlrlbasetag := false

	singletag := false  //定义是否在解析单项配置如单个地址池、单个apn
	isakmpworking := "" //定义isakmp具体单个解析类型

	var singleapn Apnmaininfo
	var singletunnel Tunnelinfo
	var singleipv4pool Ipv4poolinfo
	var singleisakmpprofile Isakmpprofile
	var singleisakmppolicy string
	var singleisakmpkeyset string
	var singleipsecprofile Ipsecprofile
	var singletransformset string
	var singleipv4acl string
	var singleospfidinfo Ospfidinfo
	var singledpitemplate Dpitemplate
	var singlerulebasetml Rulebasetemplate
	var tempname string //通用临时名称，用于记录解读配置文件时某些命名以便放到map中
	var thepgw string

	var alltunnels = make(map[string]Tunnelinfo)           //隧道名称和隧道信息映射表
	var allipv4pools = make(map[string]Ipv4poolinfo)       //地址池名称和地址信息映射表
	var vrftunnel = make(map[string]string)                //vrf和隧道类型映射表
	var allisakmpprofiles = make(map[string]Isakmpprofile) //isakmpprofile名称和信息映射表
	var allisakmppolicies = make(map[string]string)        //isakmppolicy名称和信息映射表
	var allisakmpkeysets = make(map[string]string)         //isakmpkeyset名称和信息映射表，其中key为加密信息需要从外部导入
	var allipsecprofiles = make(map[string]Ipsecprofile)   //ipsecprofile名称和信息映射表
	var alltransformsets = make(map[string]string)         //Transformset名称和信息映射表
	var allipv4acls = make(map[string]string)              //acl名称和信息映射表
	var allospfids = make(map[string]Ospfidinfo)           //ospf id和信息映射表

	var dpidomaininfo = make(map[string]string)        //dpi域名信息
	var dpil34info = make(map[string]Dpil34filterinfo) //dpi三层过滤器
	var dpil7info = make(map[string]string)            //dpi七层url信息，只提取url字段
	var dpil34ginfo = make(map[string][]string)        //dpi三层过滤组
	var dpil7ginfo = make(map[string][]string)         //dpi七层过滤组
	var dpiruleinfo = make(map[string][]Dpirule)       //dpi规则信息
	var dpitemplateinfo = make(map[string]Dpitemplate) //dpi模板信息
	//charge-rule 不采集，自动根据业务id生成
	var pccrbtemplateinfo = make(map[string]Rulebasetemplate) //通用apn的rulebase模板信息，里面定义了dpi模板信息和预定义计费控制规则（组）
	var apnccrinfo = make(map[string][]Pccccr)                //专用apn的计费控制信息
	var apnpccbrteminfo = make(map[string][]string)           //通用apn下关联的rulebase模板信息
	var ruconnrutmlinfo = make(map[string]string)             //预定义规则组和rulebase模板关联关系
	singlepccccr := []Pccccr{}
	singlepccbrtem := []string{}

	for {
		if !buf.Scan() {
			break //文件读完了,退出for
		}
		line := buf.Text() //获取每一行

		if line == "!<if-intf>" { //接口配置开始

			interfacetag = true
			log.Println(makenowstring() + " " + thepgw + " 开始读取interface接口配置...")
			continue

		}
		if line == "!</if-intf>" { //接口配置结束

			interfacetag = false
			log.Println(makenowstring() + " " + thepgw + " 完成interface接口配置读取和解析")
			continue

		}

		if line == "!<isakmp>" { //isakmp配置开始

			isakmptag = true
			log.Println(makenowstring() + " " + thepgw + " 开始读取isakmp配置...")
			continue

		}
		if line == "!</isakmp>" { //isakmp配置结束

			isakmptag = false
			log.Println(makenowstring() + " " + thepgw + " 完成isakmp配置读取和解析")
			continue

		}

		if line == "!<IPv4 Ippool Configure>" { //ipv4地址池配置开始

			ipv4pooltag = true
			log.Println(makenowstring() + " " + thepgw + " 开始读取IPV4地址池配置...")
			continue

		}
		if line == "!</IPv4 Ippool Configure>" { //ipv4地址值配置结束

			ipv4pooltag = false
			log.Println(makenowstring() + " " + thepgw + " 完成IPV4地址池配置和解析")
			continue

		}

		if line == "!<ipv4-acl>" { //ipv4 acl配置开始

			ipv4acltag = true
			log.Println(makenowstring() + " " + thepgw + " 开始读取IPV4 ACL配置...")
			continue

		}
		if line == "!</ipv4-acl>" { //ipv4 acl配置结束

			ipv4acltag = false
			log.Println(makenowstring() + " " + thepgw + " 完成IPV4 ACL配置读取和解析")
			continue

		}

		if line == "!<gre-tunnel>" { //GRE隧道配置开始

			gretunneltag = true
			log.Println(makenowstring() + " " + thepgw + " 开始读取GRE隧道配置...")
			continue

		}
		if line == "!</gre-tunnel>" { //GRE隧道配置结束

			gretunneltag = false
			log.Println(makenowstring() + " " + thepgw + " 完成GRE隧道配置读取和解析")
			continue

		}

		if line == "!<ipsec>" { //IPSEC配置开始(含ipsec隧道配置)

			ipsectag = true
			log.Println(makenowstring() + " " + thepgw + " 开始读取IPSEC配置...")
			continue

		}
		if line == "!</ipsec>" { //ipsec配置结束

			ipsectag = false
			log.Println(makenowstring() + " " + thepgw + " 完成IPSEC隧道配置读取和解析")
			continue

		}

		if line == "!<APN Configure>" { //apn配置开始

			apntag = true
			log.Println(makenowstring() + " " + thepgw + " 开始读取APN配置...")
			continue

		}
		if line == "!</APN Configure>" { //apn配置结束

			apntag = false
			log.Println(makenowstring() + " " + thepgw + " 完成所有apn配置读取和解析")
			continue

		}

		if line == "!<static>" { //读取静态路由开始

			statictag = true
			log.Println(makenowstring() + " " + thepgw + " 开始读取静态路由配置...")
			continue

		}

		if line == "!</static>" { //读取静态路由结束

			statictag = false
			log.Println(makenowstring() + " " + thepgw + " 完成静态路由配置读取和解析")
			//	log.Println(vrftunnel)
			continue

		}
		if line == "!<ospfv2>" { //读取ospf配置开始
			ospfv2tag = true
			log.Println(makenowstring() + " " + thepgw + " 开始读取ospf路由配置...")
			continue
		}

		if line == "!</ospfv2>" { //读取ospf配置结束
			ospfv2tag = false
			log.Println(makenowstring() + " " + thepgw + " 完成ospf配置读取和解析")
		}

		if line == "!<XGW DPI Configure>" { //读取dpi配置开始
			dpitag = true
			log.Println(makenowstring() + " " + thepgw + " 开始读取PGW DPI配置...")
			continue
		}

		if line == "!</XGW DPI Configure>" { //读取dpi配置开始
			dpitag = false
			log.Println(makenowstring() + " " + thepgw + " 完成PGW DPI配置读取和解析...")
			continue
		}

		if line == "!<DPI Template Configure>" { //读取dpi模板配置开始
			dpitmltag = true
			log.Println(makenowstring() + " " + thepgw + " 开始读取DPI模板配置...")
			continue
		}

		if line == "!</DPI Template Configure>" { //读取dpi模板配置开始
			dpitmltag = false
			log.Println(makenowstring() + " " + thepgw + " 完成DPI模板配置读取和解析...")
			continue
		}

		if line == "!<Rulebase template Configure>" { //读取rulebase模板配置开始
			rbtmltag = true
			log.Println(makenowstring() + " " + thepgw + " 开始读取rulebase模板配置...")
			continue
		}
		if line == "!</Rulebase template Configure>" { //读取rulebase模板配置开始
			rbtmltag = false
			log.Println(makenowstring() + " " + thepgw + " 完成rulebase模板配置读取和解析...")
			continue
		}

		if line == "!<XGW PGW Configure>" { //读取xgwpgw上的规则和rulebase模板关联关系
			rlrlbasetag = true
			log.Println(makenowstring() + " " + thepgw + " 开始读取规则和rulebase模板关联配置...")
			continue
		}

		if line == "!</XGW PGW Configure>" { //读取xgwpgw上的规则和rulebase模板关联关系
			rlrlbasetag = false
			log.Println(makenowstring() + " " + thepgw + " 完成规则和rulebase模板关联配置读取和解析...")
			continue
		}

		if strings.HasPrefix(line, "hostname ") && strings.Contains(line, "PGW") {
			thepgw = strings.Replace(line, "hostname ", "", 1)
			continue
		}
		if rlrlbasetag { //解析规则和rulebase模板关联关系
			line = strings.TrimSpace(line)
			if !strings.HasPrefix(line, "rule-map-rulebasetemplate") {
				continue
			}
			info := strings.Fields(line)
			if info[1] == "ruletype" && (info[2] == "pre-rule-group" || info[2] == "pre-rule") {
				ruconnrutmlinfo[info[3]] = info[4]
			}
			continue
		}
		if rbtmltag == true { //解析rulebase模板配置
			line = strings.TrimSpace(line)
			info := strings.Fields(line)
			if strings.HasPrefix(line, "rulebase-template") {
				singletag = true
				singlerulebasetml.Name = info[1]
				continue
			}

			if line == "$" {
				singletag = false
				pccrbtemplateinfo[singlerulebasetml.Name] = singlerulebasetml
				singlerulebasetml.Name = ""
				singlerulebasetml.Ccgr = nil
				singlerulebasetml.Ccr = nil
				singlerulebasetml.Dpitemplate = ""
				singlerulebasetml.Svclassmap = ""
				continue
			}

			if singletag {
				switch info[0] {
				case "dpi-template-rulebase":
					if info[1] == "enable" {
						singlerulebasetml.Dpitemplate = info[2]
					}
				case "service-class-map-rulebase":
					singlerulebasetml.Svclassmap = info[2]
				case "charge-control-rulebase":
					if len(info) > 5 {
						ccr := Pccccr{}
						ccr.Type = info[1]
						ccr.Name = info[2]
						ccr.Rulebaseid = info[3]
						ccr.Chargerule = info[4]
						ccr.Action = info[5]
						singlerulebasetml.Ccr = append(singlerulebasetml.Ccr, ccr)
					}
				case "charge-control-group-rulebase":
					ccgr := Pccccgr{}
					ccgr.Name = info[2]
					ccgr.Type = info[1]
					ccgr.Localccr = info[3]
					singlerulebasetml.Ccgr = append(singlerulebasetml.Ccgr, ccgr)

				}
				continue
			}

		}
		if dpitmltag == true { //解析dpi模板配置
			line = strings.TrimSpace(line)
			dpiteminfo := strings.Fields(line)
			if strings.HasPrefix(line, "template") {
				singletag = true
				singledpitemplate.Name = dpiteminfo[1]
				continue

			}

			if line == "$" {
				singletag = false
				dpitemplateinfo[singledpitemplate.Name] = singledpitemplate
				singledpitemplate.Name = ""
				singledpitemplate.Abrulebaseid = ""
				singledpitemplate.Drulebaseid = ""
				singledpitemplate.Rulebinding = nil

				continue
			}

			if singletag {
				switch dpiteminfo[0] {
				case "default-rulebaseid":
					singledpitemplate.Drulebaseid = dpiteminfo[1]
					singledpitemplate.Abrulebaseid = dpiteminfo[3]

				case "rule-binding":
					singledpitemplate.Rulebinding = append(singledpitemplate.Rulebinding, dpiteminfo[1])

				default:

				}

				continue
			}

		}

		if dpitag == true { //解析dpi配置
			line = strings.TrimSpace(line)
			dpiinfo := strings.Fields(line)
			switch dpiinfo[0] {
			case "domain":
				dpidomaininfo[dpiinfo[3]] = dpiinfo[1]

			case "l34-filter":
				sdpil34 := Dpil34filterinfo{}
				sdpil34.Apptype = dpiinfo[4]
				sdpil34.Iptype = dpiinfo[2]

				if dpiinfo[8] == "server-domain" {
					sdpil34.Sdomain = dpiinfo[9]
					sdpil34.Ssport = dpiinfo[11]
					sdpil34.Seport = dpiinfo[12]
					sdpil34.Tranp = dpiinfo[14]
				}
				if dpiinfo[8] == "serverip" {
					sdpil34.Serverip = dpiinfo[9]
					sdpil34.Ssport = dpiinfo[11]
					sdpil34.Seport = dpiinfo[12]
					sdpil34.Tranp = dpiinfo[14]
				}

				if dpiinfo[8] == "serverport" {
					sdpil34.Ssport = dpiinfo[9]
					sdpil34.Seport = dpiinfo[10]
					sdpil34.Tranp = dpiinfo[12]
				}

				dpil34info[dpiinfo[1]] = sdpil34

			case "l7-filter":
				dpil7info[dpiinfo[1]] = dpiinfo[3]

			case "filter-group":
				if dpiinfo[1] == "l34" {
					old, _ := dpil34ginfo[dpiinfo[2]]
					old = append(old, dpiinfo[3])
					dpil34ginfo[dpiinfo[2]] = old
				}
				if dpiinfo[1] == "l7" {
					old, _ := dpil7ginfo[dpiinfo[2]]
					old = append(old, dpiinfo[3])
					dpil7ginfo[dpiinfo[2]] = old
				}
			case "rule":
				srule := Dpirule{}
				srule.rulebase = dpiinfo[5]
				if dpiinfo[2] == "l34-filter-group" {
					srule.L34filterg = dpiinfo[3]
				}
				if dpiinfo[2] == "l7-filter-group" {
					srule.L7filterg = dpiinfo[3]
				}
				old, _ := dpiruleinfo[dpiinfo[1]]
				old = append(old, srule)
				dpiruleinfo[dpiinfo[1]] = old
			default:
				continue
			}
		}

		if interfacetag == true { //解析隧道和loopback接口信息，生成隧道、loopback接口名和信息map表

			if strings.HasPrefix(line, "interface gre_tunnel") || strings.HasPrefix(line, "interface ipsec_tunnel") || strings.HasPrefix(line, "interface loopback") {
				singletag = true
				singletunnel.Tunnelname = line

				alltunnels[line] = singletunnel
				continue
			}

			if line == "$" {
				singletag = false
				alltunnels[singletunnel.Tunnelname] = singletunnel
				singletunnel.Tunnelname = ""
				singletunnel.Ipaddress = ""
				singletunnel.Ip2address = ""
				singletunnel.Tunneldip = ""
				singletunnel.Tunnelvrf = ""
				singletunnel.Vrf = ""
				singletunnel.Isakmpprofile = ""
				singletunnel.Ipsecprofile = ""

				continue
			}

			if singletag {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, "ip vrf forwarding ") {
					singletunnel.Vrf = strings.Replace(line, "ip vrf forwarding ", "", 1)
					continue
				}
				if strings.HasPrefix(line, "ip address ") {
					if !strings.HasSuffix(line, " secondary") {
						singletunnel.Ipaddress = strings.Replace(line, "ip address ", "", 1)
						continue
					} else {
						singletunnel.Ip2address = strings.Replace(line, "ip address ", "", 1)
						continue
					}
				}

			}

		}

		if ospfv2tag {
			if strings.HasPrefix(line, "router ospf ") {
				singletag = true
				ospfinfo := strings.Fields(line)
				tempname = ospfinfo[2]
				singleospfidinfo.Vrf = ospfinfo[4]
				continue
			}
			if line == "$" {
				singletag = false
				allospfids[tempname] = singleospfidinfo
				singleospfidinfo.Area = ""
				singleospfidinfo.Network = nil
				singleospfidinfo.Vrf = ""
				continue
			}
			if singletag {
				if strings.HasPrefix(line, "  area ") {
					singleospfidinfo.Area = strings.Replace(line, "  area ", "", 1)
					continue
				}
				if strings.HasPrefix(line, "    network ") {
					nw := strings.Fields(line)
					if len(nw) > 2 && nw[2] == "0.0.0.0" {
						singleospfidinfo.Network = append(singleospfidinfo.Network, nw[1])
					}
					continue
				}

			}

		}

		if gretunneltag == true { //解析gre隧道详细开始
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "interface gre_tunnel") {
				singletag = true
				singletunnel = alltunnels[line]
				continue
			}
			if line == "$" {
				singletag = false
				alltunnels[singletunnel.Tunnelname] = singletunnel
				singletunnel.Tunnelname = ""
				singletunnel.Ipaddress = ""
				singletunnel.Tunneldip = ""
				singletunnel.Tunnelvrf = ""
				singletunnel.Vrf = ""
				singletunnel.Isakmpprofile = ""
				singletunnel.Ipsecprofile = ""
				continue
			}
			if singletag {
				if strings.HasPrefix(line, "tunnel vrf ") {
					singletunnel.Tunnelvrf = strings.Replace(line, "tunnel vrf ", "", 1)
					continue
				}

				if strings.HasPrefix(line, "tunnel destination ipv4 ") {
					singletunnel.Tunneldip = strings.Replace(line, "tunnel destination ipv4 ", "", 1)
					continue
				}
				if strings.HasPrefix(line, "tunnel source ipv4 ") {
					singletunnel.Tunnelsip = strings.Replace(line, "tunnel source ipv4 ", "", 1)
					continue
				}

			}

		}

		if ipsectag == true { //解析ipsec配置信息开始
			line = strings.TrimSpace(line)

			if strings.HasPrefix(line, "interface ipsec_tunnel") {
				singletag = true
				singletunnel = alltunnels[line]
				isakmpworking = "interface"
				continue
			}
			if strings.HasPrefix(line, "crypto ipsec transform-set ") {
				singletag = true
				isakmpworking = "transformset"
				tempname = strings.Replace(line, "crypto ipsec transform-set ", "", 1)
				continue
			}
			if strings.HasPrefix(line, "crypto ipsec static-profile ") {
				singletag = true
				isakmpworking = "ipsecprofile"
				tempname = strings.Replace(line, "crypto ipsec static-profile ", "", 1)

			}
			if line == "$" {
				if singletag == false {
					continue
				}
				switch isakmpworking {
				case "interface":
					alltunnels[singletunnel.Tunnelname] = singletunnel
					singletunnel.Tunnelname = ""
					singletunnel.Ipaddress = ""
					singletunnel.Tunneldip = ""
					singletunnel.Tunnelvrf = ""
					singletunnel.Vrf = ""
					singletunnel.Isakmpprofile = ""
					singletunnel.Ipsecprofile = ""
				case "transformset":
					alltransformsets[tempname] = singletransformset
					singletransformset = ""
				case "ipsecprofile":
					allipsecprofiles[tempname] = singleipsecprofile
					singleipsecprofile.Acl = ""
					singleipsecprofile.Pfs = ""
					singleipsecprofile.Salifetime = ""
					singleipsecprofile.Transformset = ""
				}
				singletag = false
				isakmpworking = ""
				tempname = ""
				continue
			}
			if singletag {
				if isakmpworking == "interface" && strings.HasPrefix(line, "tunnel vrf ") {
					singletunnel.Tunnelvrf = strings.Replace(line, "tunnel vrf ", "", 1)
					continue
				}

				if isakmpworking == "interface" && strings.HasPrefix(line, "tunnel remote ipv4-address ") {
					singletunnel.Tunneldip = strings.Replace(line, "tunnel remote ipv4-address ", "", 1)
					continue
				}
				if isakmpworking == "interface" && strings.HasPrefix(line, "tunnel local ipv4-address ") {
					singletunnel.Tunnelsip = strings.Replace(line, "tunnel local ipv4-address ", "", 1)
					continue
				}
				if isakmpworking == "interface" && strings.HasPrefix(line, "isakmp-profile ") {
					singletunnel.Isakmpprofile = strings.Replace(line, "isakmp-profile ", "", 1)
					continue
				}
				if isakmpworking == "interface" && strings.HasPrefix(line, "ipsec-profile ") {
					singletunnel.Ipsecprofile = strings.Replace(line, "ipsec-profile ", "", 1)
					continue
				}
				if isakmpworking == "transformset" {
					singletransformset += line
					singletransformset += "\n"
					continue
				}
				if isakmpworking == "ipsecprofile" && strings.HasPrefix(line, "set transform-set ") {
					singleipsecprofile.Transformset = strings.Replace(line, "set transform-set ", "", 1)
					continue
				}
				if isakmpworking == "ipsecprofile" && strings.HasPrefix(line, "set sa lifetime seconds ") {
					singleipsecprofile.Salifetime = strings.Replace(line, "set sa lifetime seconds ", "", 1)
					continue
				}
				if isakmpworking == "ipsecprofile" && strings.HasPrefix(line, "set pfs ") {
					singleipsecprofile.Pfs = strings.Replace(line, "set pfs ", "", 1)
					continue
				}
				if isakmpworking == "ipsecprofile" && strings.HasPrefix(line, "match acl ") {
					singleipsecprofile.Acl = strings.Fields(line)[2]
					continue
				}

			}

		}

		if statictag == true { //解析具体静态路由表，生成vrf和隧道类型map表

			if strings.HasPrefix(line, "ip route vrf ") {
				line = strings.Replace(line, "ip route vrf ", "", 1)
				sinfo := strings.Fields(line)
				if len(sinfo) > 2 {
					vrf := sinfo[0]
					if strings.Contains(line, "gre_tunnel") {
						vrftunnel[vrf] = "GRE"
					}
					if strings.Contains(line, "ipsec_tunnel") {
						vrftunnel[vrf] = "IPSEC"
					}
				}
				continue
			}

		}

		if ipv4acltag {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "ipv4-access-list ") {
				singletag = true
				tempname = strings.Replace(line, "ipv4-access-list ", "", 1)
				continue
			}

			if line == "$" {
				allipv4acls[tempname] = singleipv4acl
				tempname = ""
				singleipv4acl = ""
				singletag = false
				continue
			}

			if singletag {
				singleipv4acl += line
				singleipv4acl += "\n" //增加换行符便于直接引用生成脚本
				continue
			}

		}

		if isakmptag {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "isakmp profile ") {
				singletag = true
				tempname = strings.Replace(line, "isakmp profile ", "", 1)
				isakmpworking = "isakmpprofile"
				continue
			}

			if strings.HasPrefix(line, "isakmp policy ") {
				singletag = true
				tempname = strings.Replace(line, "isakmp policy ", "", 1)
				isakmpworking = "isakmppolicy"
				continue
			}

			if strings.HasPrefix(line, "isakmp key-set ") {
				singletag = true
				tempname = strings.Replace(line, "isakmp key-set ", "", 1)
				isakmpworking = "isakmpkeyset"
				continue
			}

			if line == "$" {
				if singletag == false { //连续出现两个$,第二个时跳过
					continue
				}
				switch isakmpworking {
				case "isakmpprofile":
					allisakmpprofiles[tempname] = singleisakmpprofile
					singleisakmpprofile.Keyset = ""
					singleisakmpprofile.Matchid = ""
					singleisakmpprofile.Policy = ""
				case "isakmppolicy":
					allisakmppolicies[tempname] = singleisakmppolicy
					singleisakmppolicy = ""
				case "isakmpkeyset":
					allisakmpkeysets[tempname] = singleisakmpkeyset
					singleisakmpkeyset = ""
				}
				tempname = ""
				singletag = false
				isakmpworking = ""
				continue
			}

			if singletag {
				if isakmpworking == "isakmpprofile" && strings.HasPrefix(line, "key-set ") {
					singleisakmpprofile.Keyset = strings.Replace(line, "key-set ", "", 1)
					continue
				}
				if isakmpworking == "isakmpprofile" && strings.HasPrefix(line, "match identity ipv4-address ") {
					singleisakmpprofile.Matchid = strings.Replace(line, "match identity ipv4-address ", "", 1)
					continue
				}
				if isakmpworking == "isakmpprofile" && strings.HasPrefix(line, "policy ") {
					singleisakmpprofile.Policy = strings.Replace(line, "policy ", "", 1)
					continue
				}
				if isakmpworking == "isakmppolicy" {
					singleisakmppolicy += line
					singleisakmppolicy += "\n" //增加换行符便于直接引用生成脚本
					continue
				}
				if isakmpworking == "isakmpkeyset" {
					if strings.HasPrefix(line, "key encrypted") == false {
						singleisakmpkeyset += line
						singleisakmpkeyset += "\n"
						continue
					}
				}
			}

		}

		if ipv4pooltag {

			if strings.HasPrefix(line, "ipv4 ip-pool ") {
				ippoolinfo := strings.Fields(line)
				singletag = true
				singleipv4pool.Poolname = ippoolinfo[3]
				singleipv4pool.Poolmode = ippoolinfo[2]
				continue
			}

			if line == "$" {
				allipv4pools[singleipv4pool.Poolname] = singleipv4pool
				singletag = false
				singleipv4pool.Poolmode = ""
				singleipv4pool.Poolname = ""
				singleipv4pool.Segment = nil
				singleipv4pool.Vrf = ""
				continue
			}

			if singletag {
				line = strings.TrimSpace(line)
				ippoolinfo := strings.Fields(line)
				if len(ippoolinfo) == 0 { //空行
					continue
				}
				switch ippoolinfo[0] {
				case "vrf":
					singleipv4pool.Vrf = strings.Replace(line, "vrf ", "", 1)
				case "segment":
					singleipv4pool.Segment = append(singleipv4pool.Segment, strings.Replace(line, "segment", "", 1))
				default:

				}
				continue
			}

		}

		if apntag == true {
			if strings.HasPrefix(line, "ap ") {
				tempname = strings.Replace(line, "ap ", "", 1)
				singletag = true

				continue
			}

			if line == "$" {
				singletag = false
				if singleapn.Tunneltype != "L2TP" {
					singleapn.Tunneltype = vrftunnel[singleapn.Vrf]
				}
				singleapn.Pgw = thepgw

				if singleapn.Tunneltype == "L2TP" {
					singleapn.Ipallocatemode = ""
				}

				if singleapn.Ipallocatemode == "radius-allocate" {
					singleapn.Ipallocatemode = "radius"
				}

				if singleapn.Ipallocatemode == "local alloc-shared-ipv4 disable" {
					singleapn.Ipallocatemode = "local"
				}

				allapns[tempname] = singleapn

				switch singleapn.Tunneltype {
				case "GRE":
					ngre += 1
				case "IPSEC":
					nipsec += 1
				case "L2TP":
					nl2tp += 1
				}

				if singleapn.Dpitemplte != "disable" {
					ndpi += 1
				}

				if allipv4pools[singleapn.Ippool].Poolmode == "assigned" {
					nassign += 1
				}
				if strings.Fields(singleapn.Authmode)[0] == "radius" {
					nradius += 1
				}

				if singleapn.Vrf == "" {
					nerror += 1
				}
				if len(singlepccccr) > 0 {
					apnccrinfo[tempname] = singlepccccr
				}
				if len(singlepccbrtem) > 0 {
					apnpccbrteminfo[tempname] = singlepccbrtem
				}

				singleapn.Vrf = ""
				singleapn.Ippool = ""
				singleapn.Ipallocatemode = ""
				singleapn.Authmode = ""
				singleapn.Tunneltype = ""
				singleapn.Chargeonline = ""
				singleapn.Dpitemplte = ""
				singleapn.Pdns = ""
				singleapn.Sdns = ""
				singleapn.Pdnsv6 = ""
				singleapn.Sdnsv6 = ""
				singleapn.Radiuscharging = ""
				singleapn.Aaaprofile = ""
				singleapn.Attrpriority = ""
				singleapn.L2tpinfo = ""
				singleapn.Pppauthchap = ""
				singleapn.Pppauthpap = ""
				singleapn.Pppregen = ""
				singleapn.Pppoption = ""
				singlepccccr = nil
				singlepccbrtem = nil
				tempname = ""

				continue
			}

			if singletag {
				line = strings.TrimSpace(line)
				apninfo := strings.Fields(line)
				if len(apninfo) == 0 { //空行
					continue
				}
				switch apninfo[0] { //第一个特征字段
				case "vrf":
					singleapn.Vrf = strings.Replace(line, "vrf ", "", 1)
				case "ippool":
					singleapn.Ippool = strings.Replace(line, "ippool ", "", 1)
				case "ip-allocate-mode":
					singleapn.Ipallocatemode = strings.Replace(line, "ip-allocate-mode ", "", 1)
				case "authentication-mode":
					singleapn.Authmode = strings.Replace(line, "authentication-mode ", "", 1)
				case "l2tp":
					singleapn.L2tpinfo += (line + "\n")
					if strings.HasPrefix(line, "l2tp lns-ip-address ") {
						singleapn.Tunneltype = "L2TP"
					}
				case "service-class-map":
					if len(apninfo) > 2 {
						singleapn.Svclassmap = apninfo[2]
					}
				case "ppp-regeneration":
					singleapn.Pppregen += (line + "\n")
				case "ppp-option":
					singleapn.Pppoption = (line + "\n")
				case "ppp":
					if apninfo[1] == "authentication-chap" {
						singleapn.Pppauthchap = apninfo[2]

					}
					if apninfo[1] == "authentication-pap" {
						singleapn.Pppauthpap = apninfo[2]
					}
				case "charge":
					if apninfo[1] == "charging-mode" {
						line = strings.Replace(line, "charge charging-mode ", "", 1)
						chargeinfo := strings.Fields(line)
						singleapn.Chargeonline = chargeinfo[1]
						singleapn.Dpitemplte = chargeinfo[3]
					}
					if apninfo[1] == "radius-charging" {
						singleapn.Radiuscharging = strings.Replace(line, "charge radius-charging ", "", 1)
					}
					if apninfo[1] == "aaa-profile" {
						singleapn.Aaaprofile = strings.Replace(line, "charge aaa-profile ", "", 1)
					}
				case "primary-dns-v6":
					singleapn.Pdnsv6 = strings.Replace(line, "primary-dns-v6 ", "", 1)
				case "secondary-dns-v6":
					singleapn.Sdnsv6 = strings.Replace(line, "secondary-dns-v6 ", "", 1)
				case "primary-dns":
					singleapn.Pdns = strings.Replace(line, "primary-dns ", "", 1)
				case "secondary-dns":
					singleapn.Sdns = strings.Replace(line, "secondary-dns ", "", 1)
				case "attribute-priority":
					singleapn.Attrpriority = strings.Replace(line, "attribute-priority ", "", 1)
				case "pcc":
					if apninfo[1] == "rule-map-rulebasetemplate" {
						if apninfo[2] == "disable" {
							singleapn.Typeofapn = "专用"
							nzhuan += 1
						} else {
							singleapn.Typeofapn = "通用"
							ncommon += 1
						}
					}
				case "charge-control":
					if len(apninfo) > 5 {
						spccccr := Pccccr{}
						spccccr.Type = apninfo[1]
						spccccr.Name = apninfo[2]
						spccccr.Rulebaseid = apninfo[3]
						spccccr.Chargerule = apninfo[4]
						spccccr.Action = apninfo[5]
						singlepccccr = append(singlepccccr, spccccr)
					}
				case "rulebasemapping":
					if apninfo[1] == "enable" {
						tempstr := apninfo[2]
						singlepccbrtem = append(singlepccbrtem, tempstr)
					}

				default:
					continue

				}
				continue

			}

		}

	}

	numapn.numgre = ngre
	numapn.numl2tp = nl2tp
	numapn.numipsec = nipsec
	numapn.numassign = nassign
	numapn.numradius = nradius
	numapn.numerror = nerror
	numapn.common = ncommon
	numapn.zhuan = nzhuan
	numapn.numdpi = ndpi
	return thepgw, allapns, alltunnels, numapn, ruconnrutmlinfo, dpidomaininfo, dpil34info, dpil7info, dpil34ginfo, dpil7ginfo, dpiruleinfo, dpitemplateinfo, pccrbtemplateinfo, apnccrinfo, apnpccbrteminfo

}
