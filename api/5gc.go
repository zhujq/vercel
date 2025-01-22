package handler

import (
	"archive/zip"
	"bufio"
	"bytes"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gen2brain/go-unarr"
)

type Tunnelinfo struct {
	Tunnelvrf string
	Tunnelsip string
	Tunneldip string
}

type Interfaceinfo struct {
	Vrf  string
	Ipv4 []string
	Ipv6 []string
}

type Ipv6staticinfo struct {
	Dest    string
	Nextins string
	Nexthop string
	Bfd     bool
}

type Ipv4staticinfo struct {
	Dest    string
	Mask    string
	Nextins string
	Nexthop string
	Bfd     bool
	Metric  int
}

type Logicipinfo struct {
	Typeofip  string
	Ipaddress string
	Addrtype  string
}

type Ippoolinfo struct {
	Attr   string
	Iptype string
}

type Ipseginfo struct {
	Startip string
	Endip   string
	Mask    string
	Ins     string
}

type Ipv6seginfo struct {
	Ipv6prefix    string
	Ipv6prefixlen string
	Ins           string
}

type L2tplacinfo struct {
	Ipv4oflac string
	Ipv6oflac string
	Ins       string
}

type L2tplnsinfo struct {
	Ipaddr string
	Iptype string
}

type L2tpconninfo struct {
	Lacinfo string
	Lnsinfo string
}

type Upfconnsmfinfo struct {
	Ipversion string
	Ipaddr    string
	Netins    string
}

type Nrfinfo struct {
	Nrfipaddr string
	Nrfport   string
}

type Vnfinfo struct {
	Vnfname           string                      //网元名称
	Vnfmgtip          string                      //网元和EMS互联的管理地址
	Vnfslbip          []string                    //AMF/SMF网元的SLB业务地址
	Vnfrole           []string                    //网元角色，如PGW-U/SGW-u/UPF
	Dnn               []string                    //网元部署的DNN/APN列表
	Netins            []string                    //网元配置的网络实例
	Netinstovrf       map[string]string           //网络实例映射vrf名称
	Dnntonetins       map[string]string           //DNN映射网络实例名称
	Instologic        map[string][]Logicipinfo    //网络实例为key，value为业务地址，包括SET UPASSOCADDR设置的N4地址
	Vrfofrosng        []string                    //rosng里定义的vrf列表
	Infofrosng        map[string]Interfaceinfo    //接口名称为key
	Greofrosng        map[string]Tunnelinfo       //gre隧道名称为key
	Ipsecofrosng      map[string]Tunnelinfo       //ipsec隧道名称为key
	Ipv6staticofrosng map[string][]Ipv6staticinfo //vrf为key,ipv6静态路由信息切片为value
	Ipv4staticofrosng map[string][]Ipv4staticinfo //vrf为key,ipv4静态路由信息切片为value
	Ippoolpmenlist    []string                    //启用性能统计的IP地址池列表
	Apnpmenlist       []string                    //启用性能统计的apn列表,可以遍历是否所有apn/dnn都启用性能统计
	Ippool            map[string]Ippoolinfo       //IP地址池信息表，key为pool名称
	Ippooltoseg       map[string][]Ipseginfo      //ip地址池到网段映射
	Ippooltoseg6      map[string][]Ipv6seginfo    //ipv6地址池到网段映射
	Apndnntoippool    map[string][]string         //apn到一个或多个ippool地址池映射
	L2tplac           map[string]L2tplacinfo      //l2tplac信息表，key为l2tplac名称
	L2tplns           map[string]L2tplnsinfo      //l2tplns信息表，key为l2tplns名称
	L2tpapnconn       map[string]L2tpconninfo     //l2tpapnconn信息表，key为apn名称
	Upfconnsmf        map[string]Upfconnsmfinfo   //upf连接的smf信息表，key为smf名称
	Nrf               []Nrfinfo                   //nrf信息表
	Commconfig        map[string][]string         //其他配置保存到map中，key为--后面的字符
}

type L34filter struct {
	Type       string //IPV4、IPV6、Domain
	Ipaddress  string
	Mask       string
	Domainname string
	Protocol   string
	Startport  string
	Endport    string
}

type L7filter struct {
	Url     string
	Method  string
	Apptype string
}

type Filterflow struct {
	L34filterg string
	L7filterg  string
}

type Trafficcontrol struct {
	Action     string
	Headenrich string
}

type Httpheaden struct {
	Datatype string
	Prefix   string
}

type Chargedata struct {
	Offlineurrid string
	Onlineurrid  string
	N40onurrid   string
	N40onsiurrid string
}

type Ruleinfo struct {
	Filtercontrol string
	Trafcontrol   string
	Qoscontrol    string
	Chargecontrol string
}

type Dpiinfo struct {
	Domaininfo      map[string]string     //域名配置
	L34filterinfo   map[string]L34filter  //L34配置
	L7filterinfo    map[string]L7filter   //L7配置
	L34filterginfo  map[string][]string   //L34过滤组配置
	L7filterginfo   map[string][]string   //L7过滤组配置
	Filterflowinfo  map[string]Filterflow //流过滤器配置
	Filterflowlinfo map[string][]string   //流过滤器组配置
	//以上为流过滤相关配置，定义了需匹配的流量特征
	Qosinfo map[string]string //qos配置，决定匹配的业务流的qos参数，当前只检查gate

	Httpheadeninfo map[string][]Httpheaden   //http头增强模版配置
	Headenrichinfo map[string]string         //头增强策略配置
	Trafficinfo    map[string]Trafficcontrol //业务流控制策略，决定匹配的业务流是否转发，是否进行头增强

	Urrmapinfo map[string]string     //urr计费费率组配置
	Chargeinfo map[string]Chargedata //计费策略配置

	Rule map[string]Ruleinfo //规则配置，一个规则绑定流过滤器、qos配置、业务流控制策略、计费策略配置

	Userprofile  [4][]string //用户模版配置，定义四个切片数组，分别保持四种类型的用户模版
	Userprofileg []string    //用户模版组配置

	Rulebindup map[string][]string //用户模版和规则绑定关系,即(userprofile的用户模版或用户模版组的)名称和规则绑定

	Upbindgroup map[string][]string //用户模版组绑定关系
}

func makenowstring() (str string) {
	now := time.Now()
	h, m, s := now.Clock()
	return (strconv.Itoa(h) + ":" + strconv.Itoa(m) + ":" + strconv.Itoa(s))
}

func diffstr(s1, s2 []string) []string {
	diff := []string{}

	for _, i := range s1 {
		found := false
		for _, j := range s2 {
			if i == j {
				found = true
				break
			}
		}
		if !found {
			diff = append(diff, i)
		}
	}

	return diff
}

func ContainsString(src []string, dest string) bool {
	for _, item := range src {
		if item == dest {
			return true
		}
	}
	return false
}

// DifferenceStrings 取前者src与后者dest两个字符串列表的差集
func DifferenceStrings(src []string, dest []string) []string {
	res := make([]string, 0)
	for _, item := range src {
		if !ContainsString(dest, item) {
			res = append(res, item)
		}
	}
	return res
}

// IntersectionStrings 取两个字符串列表的交集
func jiaojistr(src []string, dest []string) []string {
	res := make([]string, 0)
	for _, item := range src {
		if ContainsString(dest, item) {
			res = append(res, item)
		}
	}
	return res
}

// UnionString 取两个字符串列表的并集
func unionstr(src []string, dest []string) []string {
	res := make([]string, 0)
	res = append(res, src...)
	for _, item := range dest {
		if !ContainsString(res, item) {
			res = append(res, item)
		}
	}
	return res
}

func strissame(strs ...string) bool {
	if len(strs) <= 1 {
		return true // 如果少于2个字符串，则默认它们都相同
	}
	base := strs[0]
	for _, str := range strs[1:] {
		if str != base {
			return false // 一旦发现不同的字符串，返回false
		}
	}
	return true // 所有字符串都相同
}

func decodevnf(buf *bufio.Scanner) (*Dpiinfo, *Vnfinfo) {

	dpiinfo := Dpiinfo{
		Domaininfo:      make(map[string]string),
		L34filterinfo:   make(map[string]L34filter),
		L7filterinfo:    make(map[string]L7filter),
		L34filterginfo:  make(map[string][]string),
		L7filterginfo:   make(map[string][]string),
		Filterflowinfo:  make(map[string]Filterflow),
		Filterflowlinfo: make(map[string][]string),
		Qosinfo:         make(map[string]string),
		Rule:            make(map[string]Ruleinfo),
		Httpheadeninfo:  make(map[string][]Httpheaden),
		Headenrichinfo:  make(map[string]string),
		Trafficinfo:     make(map[string]Trafficcontrol),
		Urrmapinfo:      make(map[string]string),
		Chargeinfo:      make(map[string]Chargedata),
		Rulebindup:      make(map[string][]string),
		Upbindgroup:     make(map[string][]string),
		Userprofile:     [4][]string{},
	}
	vnfinfo := Vnfinfo{
		Vnfname:           "",
		Netinstovrf:       make(map[string]string),
		Dnntonetins:       make(map[string]string),
		Instologic:        make(map[string][]Logicipinfo),
		Infofrosng:        make(map[string]Interfaceinfo),
		Greofrosng:        make(map[string]Tunnelinfo),
		Ipsecofrosng:      make(map[string]Tunnelinfo),
		Ipv6staticofrosng: make(map[string][]Ipv6staticinfo),
		Ipv4staticofrosng: make(map[string][]Ipv4staticinfo),
		Ippool:            make(map[string]Ippoolinfo),
		Ippooltoseg:       make(map[string][]Ipseginfo),
		Ippooltoseg6:      make(map[string][]Ipv6seginfo),
		Apndnntoippool:    make(map[string][]string),
		L2tplac:           make(map[string]L2tplacinfo),
		L2tplns:           make(map[string]L2tplnsinfo),
		L2tpapnconn:       make(map[string]L2tpconninfo),
		Upfconnsmf:        make(map[string]Upfconnsmfinfo),
		Commconfig:        make(map[string][]string),
	}

	nfsname := ""
	stackmode := ""    //解析协议栈模式控制开关和协议栈解析内容控制，为空表示不在协议栈解析模式，有值如vrf时表示正在解析vrf内容
	singletag := false //解析协议栈时解析到单个对象时的开关，比如解析端口信息时在解析具体某个端口
	singlename := ""   //1、解析协议栈时单个对象的名称，如端口名称 2、解析一般配置时用做map的key
	intinfo := Interfaceinfo{}
	tunnelinfo := Tunnelinfo{}
	ipv6static := Ipv6staticinfo{}
	ipv4static := Ipv4staticinfo{}
	comconfig := []string{}
	notcomm := "VNF,NF,QUORUM VM," +
		"新增域名,新增三四层过滤器,新增七层过滤规则,新增三四层过滤规则组,新增七层过滤规则组,新增流过滤器规则,新增流过滤器列表," +
		"新增QoS策略,新增规则,新增HTTP头增强模板,新增https头增强模板,新增头增强策略,新增业务流控制策略,新增计费策略," +
		"新增规则绑定关系,新增用户模板,新增用户模板组绑定关系,新增URRMAP,新增用户模板组," +
		"新增APNDNN信息配置,新增网络实例配置,新增网络实例,新增APN/DNN,新增业务地址,设置UP关联地址,新增启用地址池列表配置,新增启用APN列表配置,新增PFU Traffic信息," +
		"新增IPPD配置,新增IP地址池,新增地址池与APN/DNN关联配置,新增IPPD配置,IPv4地址段基本信息配置,IPv6地址段基本信息配置," +
		"新增L2TP LAC IP地址信息,新增LNS配置,新增L2TP配置,新增PPP over L2TP 配置,新增PPP重传配置,新增L2TPAPN," +
		"新增性能统计邻接局,新增虚机使用率告警阈值,新增虚机资源日志配置,设置虚机心跳配置,新增拨测用户配置,新增虚机内存剩余容量告警阈值,新增SC CPU告警阈值," +
		"新增SC剩余内存配额告警阈值,新增SC存储卷告警阈值,增加一个专用UDR任务,新增NF互转隧道,新增GW-U节点配置,新增CP关联地址," +
		"新增NRF服务器节点配置,新增客户端模板配置,新增服务端模板配置,"

	for {
		if !buf.Scan() {
			break //文件读完了,退出for
		}
		line := buf.Text()             //获取每一行
		line = strings.TrimSpace(line) //去掉首位的空格
		if strings.HasPrefix(line, "ENTER NFS:NAME=\"") && strings.HasSuffix(line, "\";") {
			nfsname = strings.Replace(line, "ENTER NFS:NAME=\"", "", 1)
			nfsname = strings.Replace(nfsname, "\";", "", 1)
			continue
		}
		switch nfsname {
		case "CommonS_HTTP_LB_0":
			str := strings.Split(line, "\"")
			switch str[0] {

			default:
				if strings.HasPrefix(line, "ADD SBINRFNODE:ID=") { //ADD SBINRFNODE配置无法根据str[0]命中
					if len(str) < 6 {
						continue
					}
					var nrf Nrfinfo
					nrf.Nrfipaddr = str[1]
					strs := strings.Split(str[2], ",")
					if len(strs) < 2 {
						continue
					}
					nrf.Nrfport = strings.ReplaceAll(strs[1], "SERVERPORT=", "")
					vnfinfo.Nrf = append(vnfinfo.Nrf, nrf)
				}

				if strings.HasPrefix(line, "ADD CLIENTPROFILE:ID=") || strings.HasPrefix(line, "ADD SERVERPROFILE:ID=") {
					if len(str) < 3 {
						continue
					}
					existed := false
					for _, v := range vnfinfo.Vnfslbip {
						if v == str[1] {
							existed = true
							break
						}
					}
					if !existed {
						vnfinfo.Vnfslbip = append(vnfinfo.Vnfslbip, str[1])
					}
				}

				if strings.HasPrefix(line, "--") { // --打头，表示新的配置项开始
					if singlename != "" && len(comconfig) > 0 {
						vnfinfo.Commconfig[singlename] = comconfig
						comconfig = []string{}
					}
					singlename = strings.ReplaceAll(line, "--", "")
					if strings.Contains(notcomm, (singlename + ",")) {
						singlename = ""
					}
					continue
				}
				if singlename != "" {
					comconfig = append(comconfig, line)
					continue
				}
				continue
			}

		case "CommonS_IPSEC_0":
			str := strings.Split(line, "\"")
			switch str[0] {

			default:
				if strings.HasPrefix(line, "--") { // --打头，表示新的配置项开始
					if singlename != "" && len(comconfig) > 0 {
						vnfinfo.Commconfig[singlename] = comconfig
						comconfig = []string{}
					}
					singlename = strings.ReplaceAll(line, "--", "")
					if strings.Contains(notcomm, (singlename + ",")) {
						singlename = ""
					}
					continue
				}
				if singlename != "" {
					comconfig = append(comconfig, line)
					continue
				}
				continue
			}

		case "CommonS_IPS_0":
			str := strings.Split(line, "\"")
			switch str[0] {

			default:
				if strings.HasPrefix(line, "--") { // --打头，表示新的配置项开始
					if singlename != "" && len(comconfig) > 0 {
						vnfinfo.Commconfig[singlename] = comconfig
						comconfig = []string{}
					}
					singlename = strings.ReplaceAll(line, "--", "")
					if strings.Contains(notcomm, (singlename + ",")) {
						singlename = ""
					}
					continue
				}
				if singlename != "" {
					comconfig = append(comconfig, line)
					continue
				}
				continue
			}

		case "CommonS_TMSP_0":
			if stackmode == "" {
				if strings.HasSuffix(line, "sc-tmsp-rosng") {
					stackmode = "open"
					continue
				}
				str := strings.Split(line, ":")
				switch str[0] {
				case "SET VNF":
					temp := strings.Split(line, "\"")
					for k, v := range temp {
						if v == ",DISPLAYNAME=" {
							vnfinfo.Vnfname = temp[k+1]
							break
						}
					}
				case "ADD NF":
					tempstr := strings.ReplaceAll(strings.Split(str[1], ",")[1], "ALIASNFTYPE=", "")
					tempstr = strings.ReplaceAll(tempstr, "\"", "")
					vnfinfo.Vnfrole = append(vnfinfo.Vnfrole, tempstr)
				default:
					if strings.HasPrefix(line, "--") { // --打头，表示新的配置项开始
						if singlename != "" {
							vnfinfo.Commconfig[singlename] = comconfig
							comconfig = []string{}
						}
						singlename = strings.ReplaceAll(line, "--", "")
						if strings.Contains(notcomm, (singlename + ",")) {
							singlename = ""
						}
						continue
					}
					if singlename != "" {
						comconfig = append(comconfig, line)
						continue
					}
					continue
				}

			} else { //协议栈解析模式
				if line == "!</lspm>" {
					stackmode = ""
					continue
				}
				if strings.HasPrefix(line, "!<") && !strings.HasPrefix(line, "!</") {
					stackmode = strings.ReplaceAll(line, "!<", "")
					stackmode = strings.ReplaceAll(stackmode, ">", "")
					log.Println((makenowstring() + " 开始解析" + stackmode + "的配置"))
					continue
				}
				switch stackmode {
				case "vrf":
					if strings.HasPrefix(line, "ip vrf ") {
						temp := strings.Fields(line)
						vnfinfo.Vrfofrosng = append(vnfinfo.Vrfofrosng, temp[2])
					}
					continue
				case "if-intf":
					if strings.HasPrefix(line, "interface ") {
						singletag = true
						singlename = strings.ReplaceAll(line, "interface ", "")
						continue
					}

					if line == "$" {
						vnfinfo.Infofrosng[singlename] = intinfo
						singletag = false
						singlename = ""
						intinfo = Interfaceinfo{}
						continue
					}

					if singletag {
						if strings.HasPrefix(line, "ip vrf forwarding ") {
							intinfo.Vrf = strings.ReplaceAll(line, "ip vrf forwarding ", "")
							continue
						}
						if strings.HasPrefix(line, "ip address ") {
							intinfo.Ipv4 = append(intinfo.Ipv4, strings.ReplaceAll(line, "ip address ", ""))
							continue
						}
						if strings.HasPrefix(line, "ipv6 address ") {
							intinfo.Ipv6 = append(intinfo.Ipv6, strings.ReplaceAll(line, "ipv6 address ", ""))
							continue
						}
						continue
					}
					continue
				case "gre-tunnel":
					if strings.HasPrefix(line, "interface ") {
						singletag = true
						singlename = strings.ReplaceAll(line, "interface ", "")
						continue
					}
					if line == "$" {
						vnfinfo.Greofrosng[singlename] = tunnelinfo
						singletag = false
						singlename = ""
						tunnelinfo = Tunnelinfo{}
						continue
					}
					if singletag {
						if strings.HasPrefix(line, "tunnel vrf ") {
							tunnelinfo.Tunnelvrf = strings.ReplaceAll(line, "tunnel vrf ", "")
							continue
						}
						if strings.HasPrefix(line, "tunnel source ") {
							temp := strings.Fields(line)
							if len(temp) > 3 {
								tunnelinfo.Tunnelsip = temp[3]
							}
							continue
						}
						if strings.HasPrefix(line, "tunnel destination ") {
							temp := strings.Fields(line)
							if len(temp) > 3 {
								tunnelinfo.Tunneldip = temp[3]
							}
							continue
						}
					}
					continue
				case "ipsec":
					if strings.HasPrefix(line, "interface ") {
						singletag = true
						singlename = strings.ReplaceAll(line, "interface ", "")
						continue
					}
					if line == "$" {
						vnfinfo.Ipsecofrosng[singlename] = tunnelinfo
						singletag = false
						singlename = ""
						tunnelinfo = Tunnelinfo{}
						continue
					}
					if singletag {
						if strings.HasPrefix(line, "tunnel vrf ") {
							tunnelinfo.Tunnelvrf = strings.ReplaceAll(line, "tunnel vrf ", "")
							continue
						}
						if strings.HasPrefix(line, "tunnel local ") {
							temp := strings.Fields(line)
							if len(temp) > 3 {
								tunnelinfo.Tunnelsip = temp[3]
							}
							continue
						}
						if strings.HasPrefix(line, "tunnel remote ") {
							temp := strings.Fields(line)
							if len(temp) > 3 {
								tunnelinfo.Tunneldip = temp[3]
							}
							continue
						}
					}
					continue

				case "ipv6-static-route":
					if strings.HasPrefix(line, "ipv6 route ") {
						temp := strings.Fields(line)
						if len(temp) < 7 {
							continue
						}
						ipv6static.Dest = temp[4]
						ipv6static.Nextins = temp[5]
						ipv6static.Nexthop = temp[6]
						if len(temp) > 8 && temp[7] == "track" {
							ipv6static.Bfd = true
						}
						if temp[2] == "vrf" {
							vnfinfo.Ipv6staticofrosng[temp[3]] = append(vnfinfo.Ipv6staticofrosng[temp[3]], ipv6static)
						}
						ipv6static = Ipv6staticinfo{}
						continue
					}
				case "static":
					if strings.HasPrefix(line, "ip route ") {
						temp := strings.Fields(line)
						if len(temp) < 7 {
							continue
						}
						ipv4static.Dest = temp[4]
						ipv4static.Mask = temp[5]
						ipv4static.Nextins = temp[6]
						if len(temp) > 7 {
							ipv4static.Nexthop = temp[7] //不一定配置，因此需要判断
						}
						if len(temp) > 9 && temp[8] == "track" {
							ipv4static.Bfd = true
						}
						if len(temp) > 8 && temp[7] == "metric" {
							ipv4static.Metric, _ = strconv.Atoi(temp[8])
						}
						if temp[2] == "vrf" {
							vnfinfo.Ipv4staticofrosng[temp[3]] = append(vnfinfo.Ipv4staticofrosng[temp[3]], ipv4static)
						}
						ipv4static = Ipv4staticinfo{}
					}
				default:
					continue
				}

			}

		case "Nupf_PacketForward_0":
			str := strings.Split(line, "\"")
			switch str[0] {
			case "ADD DOMAIN:NAME=":
				dpiinfo.Domaininfo[str[1]] = str[3]
				continue
			case "ADD L34FILTER:FILTERNAME=":
				if len(str) < 4 { //异常处理
					continue
				}
				var dpil34filter L34filter
				for k, v := range str {
					if v == ",IPTYPE=" {
						dpil34filter.Type = str[k+1]
						continue
					}

					if v == ",IPV4SERVERIP=" && dpil34filter.Type == "IPV4" {
						dpil34filter.Ipaddress = str[k+1]
						continue
					}
					if strings.HasSuffix(v, ",DOMAIN=") { //域名提示符和IPV4mask放在一个字符串中
						dpil34filter.Domainname = str[k+1]
						continue

					}

					if strings.HasPrefix(v, ",IPV4SERVERIPMASK=") && dpil34filter.Type == "IPV4" {
						dpil34filter.Mask = strings.ReplaceAll(strings.Split(v, ",")[1], "IPV4SERVERIPMASK=", "")
						continue
					}

					if strings.HasSuffix(v, ",IPV6SERVERIP=") && dpil34filter.Type == "IPV6" {
						dpil34filter.Ipaddress = str[k+1]
						continue
					}

					if strings.HasSuffix(v, ",PROTOCOL=") { //protocol提示符和IPV6mask放在一个字符串中
						dpil34filter.Protocol = str[k+1]
						if strings.HasPrefix(v, ",IPV6SERVERIPMASK=") && dpil34filter.Type == "IPV6" {
							dpil34filter.Mask = strings.ReplaceAll(strings.Split(v, ",")[1], "IPV6SERVERIPMASK=", "")

						}
						continue
					}

					if strings.HasSuffix(v, ",SERVERPORTSTART=") {
						dpil34filter.Startport = strings.ReplaceAll(strings.Split(v, ",")[1], "SERVERPORTSTART=", "")
						dpil34filter.Endport = strings.ReplaceAll(strings.Split(v, ",")[2], "SERVERPORTEND=", "")
						continue
					}
				}
				dpiinfo.L34filterinfo[str[1]] = dpil34filter
				dpil34filter = L34filter{}
				continue

			case "ADD L7FILTER:FILTERNAME=":
				if len(str) < 7 { //异常处理
					continue
				}
				var dpil7filter L7filter
				for k, v := range str {
					if v == ",URL=" {
						dpil7filter.Url = str[k+1]
						continue
					}
					if v == ",METHOD=" {
						dpil7filter.Method = str[k+1]
						continue
					}
					if v == ",APPTYPE=" {
						dpil7filter.Apptype = str[k+1]
						continue
					}

				}
				dpiinfo.L7filterinfo[str[1]] = dpil7filter
				dpil7filter = L7filter{}
				continue
			case "ADD L34FILTERGROUP:GROUPNAME=":
				if len(str) < 4 { //异常处理
					continue
				}
				dpiinfo.L34filterginfo[str[1]] = append(dpiinfo.L34filterginfo[str[1]], str[3])
				continue
			case "ADD L7FILTERGROUP:GROUPNAME=":
				if len(str) < 4 { //异常处理
					continue
				}
				dpiinfo.L7filterginfo[str[1]] = append(dpiinfo.L7filterginfo[str[1]], str[3])
				continue
			case "ADD FLOWFILTER:FLOWFILTERNAME=":
				if len(str) < 5 { //异常处理
					continue
				}
				var dpifilterflow Filterflow
				for k, v := range str {
					if v == ",L34FILTERGROUPNAME=" {
						dpifilterflow.L34filterg = str[k+1]
						continue
					}
					if v == ",L7FILTERGROUPNAME=" {
						dpifilterflow.L7filterg = str[k+1]
						continue
					}
				}
				dpiinfo.Filterflowinfo[str[1]] = dpifilterflow
				dpifilterflow.L34filterg = ""
				dpifilterflow.L7filterg = ""
				continue
			case "ADD FLOWFILTERLIST:LISTNAME=":
				if len(str) < 4 { //异常处理
					continue
				}
				dpiinfo.Filterflowlinfo[str[1]] = append(dpiinfo.Filterflowlinfo[str[1]], str[3])
				continue
			case "ADD QOSDATA:NAME=":
				if len(str) < 4 { //异常处理
					continue
				}
				dpiinfo.Qosinfo[str[1]] = str[3]
				continue
			case "ADD RULE:NAME=":
				if len(str) < 6 { //异常处理
					continue
				}
				var dpiruledata Ruleinfo
				for k, v := range str {
					if v == ",FLOWFILTER=" {
						dpiruledata.Filtercontrol = str[k+1]
						continue
					}
					if v == ",TRAFFICCONTROLDATA=" {
						dpiruledata.Trafcontrol = str[k+1]
						continue
					}
					if v == ",QOSDATA=" {
						dpiruledata.Qoscontrol = str[k+1]
						continue
					}
					if v == ",CHARGINGDATA=" {
						dpiruledata.Chargecontrol = str[k+1]
						continue
					}
				}
				dpiinfo.Rule[str[1]] = dpiruledata
				dpiruledata = Ruleinfo{}
				continue
			case "ADD HTTPHEADEN:NAME=":
				if len(str) < 6 { //异常处理
					continue
				}
				var dpihttpheaden Httpheaden
				dpihttpheaden.Datatype = str[3]
				dpihttpheaden.Prefix = str[5]
				dpiinfo.Httpheadeninfo[str[1]] = append(dpiinfo.Httpheadeninfo[str[1]], dpihttpheaden)
				dpihttpheaden.Datatype = ""
				dpihttpheaden.Prefix = ""
				continue
			case "ADD HTTPSHEADEN:NAME=":
				if len(str) < 6 { //异常处理
					continue
				}
				var dpihttpheaden Httpheaden
				dpihttpheaden.Datatype = str[3]
				dpihttpheaden.Prefix = strings.ReplaceAll(strings.Split(str[4], ",")[1], "SUBEXTENSIONTYPE=", "")
				dpiinfo.Httpheadeninfo[str[1]] = append(dpiinfo.Httpheadeninfo[str[1]], dpihttpheaden)
				dpihttpheaden.Datatype = ""
				dpihttpheaden.Prefix = ""
				continue
			case "ADD HEADENRICH:NAME=":
				if len(str) < 4 { //异常处理
					continue
				}
				dpiinfo.Headenrichinfo[str[1]] = str[3]
				continue
			case "ADD TRAFFICCONTROLDATA:NAME=":
				if len(str) < 4 { //异常处理
					continue
				}
				var trafficctl Trafficcontrol
				trafficctl.Action = str[3]
				for k, v := range str {
					if v == ",HEADENRICH=" {
						trafficctl.Headenrich = str[k+1]
						break
					}
				}
				dpiinfo.Trafficinfo[str[1]] = trafficctl
				trafficctl.Action = ""
				trafficctl.Headenrich = ""
				continue
			case "ADD CHARGINGDATA:NAME=":
				if len(str) < 4 { //异常处理
					continue
				}
				var chargedata Chargedata
				temp := str[2]
				temp = strings.ReplaceAll(temp, "OFFLINEURRID=", "")
				temp = strings.ReplaceAll(temp, "ONLINEURRID=", "")
				temp = strings.ReplaceAll(temp, "N40ONLINEURRID=", "")
				temp = strings.ReplaceAll(temp, "N40ONLINESIURRID=", "")
				ss := strings.Split(temp, ",")
				if len(ss) < 3 {
					continue
				}
				chargedata.Offlineurrid = ss[1]
				chargedata.Onlineurrid = ss[2]
				chargedata.N40onurrid = ss[3]
				chargedata.N40onsiurrid = ss[4]
				dpiinfo.Chargeinfo[str[1]] = chargedata
				chargedata.Offlineurrid = ""
				chargedata.Offlineurrid = ""
				chargedata.N40onurrid = ""
				chargedata.N40onsiurrid = ""
				continue
			case "ADD RULEBINDUP:UPNAME=":
				if len(str) < 4 { //异常处理
					continue
				}
				dpiinfo.Rulebindup[str[1]] = append(dpiinfo.Rulebindup[str[1]], str[3])
				continue
			case "ADD USERPROFILE:NAME=":
				if len(str) < 4 { //异常处理
					continue
				}
				switch str[3] {
				case "PREDEFINED_RULE_GROUP":
					dpiinfo.Userprofile[0] = append(dpiinfo.Userprofile[0], str[1])
				case "PREDEFINED_RULE":
					dpiinfo.Userprofile[1] = append(dpiinfo.Userprofile[1], str[1])
				case "DYNAMIC_RULE":
					dpiinfo.Userprofile[2] = append(dpiinfo.Userprofile[2], str[1])
				case "LOCAL_RULE":
					dpiinfo.Userprofile[3] = append(dpiinfo.Userprofile[3], str[1])
				}
				continue
			case "ADD USERPROFILEGROUP:NAME=":
				if len(str) != 3 { //异常处理
					continue
				}
				dpiinfo.Userprofileg = append(dpiinfo.Userprofileg, str[1])
			case "ADD UPBINDGROUP:NAME=":
				if len(str) < 4 { //异常处理
					continue
				}
				dpiinfo.Upbindgroup[str[1]] = append(dpiinfo.Upbindgroup[str[1]], str[3])
				continue
			case "ADD UPNODE:UPNAME=":
				for k, v := range str {
					if v == ",MGRIPV6VAL=" || v == ",MGRIPV4VAL=" {
						vnfinfo.Vnfmgtip = str[k+1]
						break
					}
				}
				continue
			case "ADD APNDNN:APNDNN=":
				if len(str) < 4 { //异常处理
					continue
				}
				for k, v := range str {
					if v == ",REALAPNDNN=" {
						vnfinfo.Dnn = append(vnfinfo.Dnn, str[k+1])
						break
					}
				}
				continue
			case "ADD NETWORKINSTANCE:NETWORKINSTANCE=":
				if len(str) < 2 { //异常处理
					continue
				}
				vnfinfo.Netins = append(vnfinfo.Netins, str[1])
				continue
			case "ADD VPNINSTANCE:NETWORKINSTANCE=":
				if len(str) < 4 { //异常处理
					continue
				}
				vnfinfo.Netinstovrf[str[1]] = str[3]
				continue
			case "ADD DNCFG:DNN=":
				if len(str) < 4 { //异常处理
					continue
				}
				vnfinfo.Dnntonetins[str[1]] = str[3]
				continue
			case "ADD LOGICIP:LOGICIPNAME=":
				if len(str) < 10 { //异常处理
					continue
				}
				var logicip Logicipinfo
				for k, v := range str {
					if v == ",IPVERSION=" {
						logicip.Addrtype = str[k+1]
						continue
					}
					if v == ",IPV4ADDR=" || v == ",IPV6ADDR=" {
						logicip.Ipaddress = str[k+1]
						continue
					}
					if v == ",UPINTERFACETYPE=" {
						logicip.Typeofip = str[k+1]
						continue
					}
				}
				vnfinfo.Instologic[str[5]] = append(vnfinfo.Instologic[str[5]], logicip)
				continue
			case "SET UPASSOCADDR:UPNAME=":
				if len(str) < 10 { //异常处理
					continue
				}
				var logicip Logicipinfo
				for k, v := range str {
					if v == ",IPVERSION=" {
						logicip.Addrtype = str[k+1]
						continue
					}
					if (logicip.Addrtype == "IPV4" && v == ",IPV4ADDR=") || (logicip.Addrtype == "IPV6" && v == ",IPV6ADDR=") {
						logicip.Ipaddress = str[k+1]
						continue
					}
					if v == ",NETWORKINSTANCE=" { //N4接口的networkinterface和typeofip都设置为N4
						logicip.Typeofip = str[k+1]
						continue
					}
				}
				vnfinfo.Instologic[logicip.Addrtype] = append(vnfinfo.Instologic[logicip.Addrtype], logicip)
				continue
			case "ADD IPPOOLPMENLIST:IPPOOLNAME=":
				if len(str) != 3 {
					continue
				}
				vnfinfo.Ippoolpmenlist = append(vnfinfo.Ippoolpmenlist, str[1])
				continue
			case "ADD APNPMENLIST:APNNAME=":
				if len(str) != 3 {
					continue
				}
				vnfinfo.Apnpmenlist = append(vnfinfo.Apnpmenlist, str[1])
				continue
			case "ADD IPPOOL:IPPOOLNAME=":
				if len(str) < 10 { //异常处理
					continue
				}
				ippoolinfo := Ippoolinfo{}
				for k, v := range str {
					if strings.HasSuffix(v, ",IPPOOLATTR=") {
						ippoolinfo.Attr = str[k+1]
					}
					if v == ",IPTYPE=" {
						ippoolinfo.Iptype = str[k+1]
					}
				}
				vnfinfo.Ippool[str[1]] = ippoolinfo
				continue
			case "ADD IPPOOLAPNDNNINFO:IPPOOLNAME=":
				if len(str) != 5 {
					continue
				}
				vnfinfo.Apndnntoippool[str[3]] = append(vnfinfo.Apndnntoippool[str[3]], str[1])
				continue
			case "ADD IPSEGINFO:SEGMENTNAME=":
				if len(str) < 10 { //异常处理
					continue
				}
				ippool := ""
				ipseg := Ipseginfo{}
				for k, v := range str {
					if v == ",STARTIP=" {
						ipseg.Startip = str[k+1]
						continue
					}
					if v == ",ENDIP=" {
						ipseg.Endip = str[k+1]
						continue
					}
					if v == ",MASK=" {
						ipseg.Mask = str[k+1]
						continue
					}
					if v == ",NETWORKINSTANCE=" {
						ipseg.Mask = str[k+1]
						continue
					}
					if v == ",IPPOOLNAME=" {
						ippool = str[k+1]
						continue
					}
				}
				if ippool != "" {
					vnfinfo.Ippooltoseg[ippool] = append(vnfinfo.Ippooltoseg[ippool], ipseg)
				}
				continue
			case "ADD IPV6SEGINFO:SEGMENTNAME=":
				if len(str) < 10 { //异常处理
					continue
				}
				ippool := ""
				ipseg6 := Ipv6seginfo{}
				for k, v := range str {
					if v == ",IPV6PREFIX=" {
						ipseg6.Ipv6prefix = str[k+1]
						continue
					}
					if v == ",IPV6PREFIXLEN=" {
						ipseg6.Ipv6prefixlen = str[k+1]
						continue
					}
					if v == ",NETWORKINSTANCE=" {
						ipseg6.Ins = str[k+1]
						continue
					}
				}
				if ippool != "" {
					vnfinfo.Ippooltoseg6[ippool] = append(vnfinfo.Ippooltoseg6[ippool], ipseg6)
				}
				continue
			case "ADD L2TPLAC:NAME=", "SET L2TPLAC:NAME=":
				if len(str) < 6 { //异常处理
					continue
				}
				var l2tplac L2tplacinfo
				for k, v := range str {
					if v == ",LACADDRV4=" {
						l2tplac.Ipv4oflac = str[k+1]
						continue
					}
					if v == ",LACADDRV6=" {
						l2tplac.Ipv6oflac = str[k+1]
						continue
					}
					if v == ",NETWORKINSTANCE=" {
						l2tplac.Ins = str[k+1]
						continue
					}
				}
				vnfinfo.L2tplac[str[1]] = l2tplac
				continue
			case "SET L2TPLNSIPADDR:NAME=", "ADD L2TPLNSIPADDR:NAME=":
				if len(str) < 6 { //异常处理
					continue
				}
				var l2tplns L2tplnsinfo
				for k, v := range str {
					if v == ",LNSADDR=" {
						l2tplns.Ipaddr = str[k+1]
						continue
					}
					if v == ",IPTYPE=" {
						l2tplns.Iptype = str[k+1]
						continue
					}
				}
				vnfinfo.L2tplns[str[1]] = l2tplns
				continue
			case "ADD L2TPAPN:DNN=":
				if len(str) < 6 { //异常处理
					continue
				}
				var l2tpconn L2tpconninfo
				for k, v := range str {
					if v == ",L2TPLAC=" {
						l2tpconn.Lacinfo = str[k+1]
						continue
					}
					if v == ",L2TPLNSIPADDR=" {
						l2tpconn.Lnsinfo = str[k+1]
						continue
					}
				}
				vnfinfo.L2tpapnconn[str[1]] = l2tpconn
				continue
			default:
				if strings.HasPrefix(line, "ADD URRMAP:URRID=") { //add urrmap配置无法根据str[0]命中
					strs := strings.Split(line, ",")
					if len(strs) < 5 {
						continue
					}
					dpiinfo.Urrmapinfo[strings.ReplaceAll(strs[0], "ADD URRMAP:URRID=", "")] = strings.ReplaceAll(strs[3], "RATINGGROUP=", "")
				}
				if strings.HasPrefix(line, "ADD CPASSOCADDR:CPID=") { //add CPASSOCADDR配置无法根据str[0]命中
					if len(str) < 8 { //异常处理
						continue
					}
					var connsmf Upfconnsmfinfo
					for k, v := range str {
						if v == ",IPVERSION=" {
							connsmf.Ipversion = str[k+1]
							connsmf.Ipaddr = str[k+3]
							continue
						}
						if v == ",NETWORKINSTANCE=" {
							connsmf.Netins = str[k+1]
							continue
						}
					}
					vnfinfo.Upfconnsmf[str[1]] = connsmf
					continue

				}
				if strings.HasPrefix(line, "--") { // --打头，表示新的配置项开始
					if singlename != "" && len(comconfig) > 0 {
						vnfinfo.Commconfig[singlename] = comconfig
						comconfig = []string{}
					}
					singlename = strings.ReplaceAll(line, "--", "")
					if strings.Contains(notcomm, (singlename + ",")) {
						singlename = ""
					}
					if strings.HasSuffix(singlename, " Custom Export Mmls") {
						singlename = ""
					}
					continue
				}
				if singlename != "" {
					comconfig = append(comconfig, line)
					continue
				}
				continue
			}
		default:
			if strings.HasPrefix(line, "--") { // --打头，表示新的配置项开始
				if singlename != "" && len(comconfig) > 0 {
					vnfinfo.Commconfig[singlename] = comconfig
					comconfig = []string{}
				}
				singlename = strings.ReplaceAll(line, "--", "")
				if strings.Contains(notcomm, (singlename + ",")) {
					singlename = ""
				}
				continue
			}
			if singlename != "" {
				comconfig = append(comconfig, line)
				continue
			}
			continue
		}

	}
	return &dpiinfo, &vnfinfo
}

func procRequest(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		filepath := r.URL.Path
		log.Println(filepath)
		switch filepath {
		case "/favicon.ico":
			filepath = "./lib/favicon.ico"
		case "/ht.js":
			filepath = "./lib/ht.js"
		case "/draw.html":
			filepath = "./draw.html"
		default:
			filepath = "./input.html"
		}
		content, err := os.ReadFile(filepath)
		if err != nil {
			http.Error(w, "File reading error", http.StatusInternalServerError)
			return
		}
		w.Write(content)

	case "POST":
		log.Println(makenowstring() + " 开始接收上传的文件。")
		err := r.ParseMultipartForm(100 * 1024 * 1024) // 100 MB is the maximum file size
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		dpidata := make([]*Dpiinfo, 0) //指向解析多套网元DPI和网元结果的指针切片
		vnfdata := make([]*Vnfinfo, 0)
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

		log.Println(makenowstring() + " 开始读取5GC配置反导文件：" + handler.Filename + " ....")
		if strings.HasSuffix(handler.Filename, "7z") { //unarr解压zip文件有问题，分开处理
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
				dpi, vnf := decodevnf(reader)
				dpidata = append(dpidata, dpi)
				vnfdata = append(vnfdata, vnf)
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
				dpi, vnf := decodevnf(buf)
				dpidata = append(dpidata, dpi)
				vnfdata = append(vnfdata, vnf)

			}
		} else {
			buf := bufio.NewScanner(file)
			dpi, vnf := decodevnf(buf)
			dpidata = append(dpidata, dpi)
			vnfdata = append(vnfdata, vnf)
		}
		tempstr := ""
		switch r.Form.Get("mode") {
		case "decode":
			log.Println(makenowstring() + " 配置文件读取完毕，开始生成主要配置结果" + handler.Filename + " ....")
			for index, v := range vnfdata {
				tempstr += vnfdata[index].Vnfname
				for k, vv := range v.Vnfrole {
					tempstr += vv
					if k < len(vnfdata[index].Vnfrole)-1 {
						tempstr += "&"
					} else {
						tempstr += ")"
					}
				}
				tempstr += ",该网元业务地址如下(网络实例-IP地址-逻辑接口)：\r\n"
				for k, vv := range v.Instologic {
					for _, vvv := range vv {
						tempstr += k
						tempstr += "-"
						tempstr += vvv.Ipaddress
						tempstr += "-"
						tempstr += vvv.Typeofip
						tempstr += "\r\n"
					}
				}
				tempstr += "\r\n该网元定义的APN-VRF关系如下：\r\n"

				for _, vv := range v.Dnn {
					tempstr += vv
					tempstr += "-->"
					tempstr += v.Netinstovrf[vnfdata[index].Dnntonetins[vv]]
					tempstr += "\r\n"
				}

				if len(v.Nrf) > 0 {
					tempstr += "Nrf信息："
					for _, vv := range v.Nrf {
						tempstr += vv.Nrfipaddr
						tempstr += "/"
						tempstr += vv.Nrfport
						tempstr += "\r\n"
					}
				}
			}

		case "find":
			log.Println(makenowstring() + " 配置文件读取完毕，开始分析是否存在配置错误" + handler.Filename + " ....")
			for index, v := range dpidata {
				var diff []string
				var domain []string
				var l34domain []string
				var l34name []string
				var l34nameofl34g []string
				var l7name []string
				var l7nameofl7g []string
				var l34gname []string
				var l34gnameoflow []string
				var l7gname []string
				var l7gnameoflow []string
				var flowname []string
				var flowlname []string
				var flownameofflowl []string
				var flownameofrule []string
				var rulename []string
				var rulenameofbind []string
				var userprofile []string
				var userprofileg []string

				tempstr += vnfdata[index].Vnfname
				tempstr += "("
				for k, v := range vnfdata[index].Vnfrole {
					tempstr += v
					if k < len(vnfdata[index].Vnfrole)-1 {
						tempstr += "&"
					} else {
						tempstr += ")"
					}
				}

				tempstr += "该UPF的DPI分析结果：\r\n"
				tempstr += "domain域名定义了"
				for k, _ := range v.Domaininfo {
					domain = append(domain, k)
				}
				tempstr += strconv.Itoa(len(domain))
				tempstr += "个，"

				for _, vv := range v.L34filterinfo {
					if vv.Domainname != "" {
						l34domain = append(l34domain, vv.Domainname)
					}
				}

				diff = diffstr(domain, l34domain)
				if len(diff) == 0 {
					tempstr += "定义的域名全部被L34过滤规则引用。\r\n"
				} else {
					tempstr += "其中以下域名定义了但未被L34规则引用:\r\n"
					for _, v := range diff {
						tempstr += v
						tempstr += "\r\n"
					}
				}

				tempstr += "L34过滤规则定义了"
				for k, _ := range v.L34filterinfo {
					l34name = append(l34name, k)
				}
				for _, vv := range v.L34filterginfo {
					for _, vvv := range vv {
						l34nameofl34g = append(l34nameofl34g, vvv)
					}
				}
				tempstr += strconv.Itoa(len(l34name))
				tempstr += "个，"
				diff = diffstr(l34name, l34nameofl34g)
				if len(diff) == 0 {
					tempstr += "定义的L34过滤规则全部被L34过滤规则组引用。\r\n"
				} else {
					tempstr += "其中以下L34过滤规则定义了但未被L34过滤规则组引用:\r\n"
					for _, v := range diff {
						tempstr += v
						tempstr += "\r\n"
					}
				}

				tempstr += "L7过滤规则定义了"
				for k, _ := range v.L7filterinfo {
					l7name = append(l7name, k)
				}
				for _, vv := range v.L7filterginfo {
					for _, vvv := range vv {
						l7nameofl7g = append(l7nameofl7g, vvv)
					}
				}
				tempstr += strconv.Itoa(len(l7name))
				tempstr += "个，"
				diff = diffstr(l7name, l7nameofl7g)
				if len(diff) == 0 {
					tempstr += "定义的L7过滤规则全部被L7过滤规则组引用。\r\n"
				} else {
					tempstr += "其中以下L7过滤规则定义了但未被L7过滤规则组引用:\r\n"
					for _, v := range diff {
						tempstr += v
						tempstr += "\r\n"
					}
				}

				tempstr += "L34过滤规则组定义了"
				for k, _ := range v.L34filterginfo {
					l34gname = append(l34gname, k)
				}
				for _, vv := range v.Filterflowinfo {
					if vv.L34filterg != "" {
						l34gnameoflow = append(l34gnameoflow, vv.L34filterg)
					}
				}
				tempstr += strconv.Itoa(len(l34gname))
				tempstr += "个，"
				diff = diffstr(l34gname, l34gnameoflow)
				if len(diff) == 0 {
					tempstr += "定义的L34过滤规则组全部被流过滤器引用。\r\n"
				} else {
					tempstr += "其中以下L34过滤规则组定义了但未被流过滤器引用:\r\n"
					for _, v := range diff {
						tempstr += v
						tempstr += "\r\n"
					}
				}

				tempstr += "L7过滤规则组定义了"
				for k, _ := range v.L7filterginfo {
					l7gname = append(l7gname, k)
				}
				for _, vv := range v.Filterflowinfo {
					if vv.L7filterg != "" {
						l7gnameoflow = append(l7gnameoflow, vv.L7filterg)
					}
				}
				tempstr += strconv.Itoa(len(l7gname))
				tempstr += "个，"
				diff = diffstr(l7gname, l7gnameoflow)
				if len(diff) == 0 {
					tempstr += "定义的L7过滤规则组全部被流过滤器引用。\r\n"
				} else {
					tempstr += "其中以下L7过滤规则组定义了但未被流过滤器引用:\r\n"
					for _, v := range diff {
						tempstr += v
						tempstr += "\r\n"
					}
				}

				tempstr += "流过滤器定义了"
				for k, _ := range v.Filterflowinfo {
					flowname = append(flowname, k)
				}
				for k, _ := range v.Filterflowlinfo {
					flowlname = append(flowlname, k)
				}
				for _, vv := range v.Filterflowlinfo {
					for _, vvv := range vv {
						flownameofflowl = append(flownameofflowl, vvv)
					}
				}
				for _, vv := range v.Rule {
					if vv.Filtercontrol != "" {
						flownameofrule = append(flownameofrule, vv.Filtercontrol)
					}
				}
				tempstr += strconv.Itoa(len(flowname))
				tempstr += "个，"
				diff = diffstr(flowname, flownameofrule)
				diff = diffstr(diff, flownameofflowl) //流过滤器也可能被流过滤器组引用
				if len(diff) == 0 {
					tempstr += "定义的流过滤器全部被rule规则和流过滤器组引用。\r\n"
				} else {
					tempstr += "其中以下流过滤器定义了但未被rule规则和流过滤器组引用:\r\n"
					for _, v := range diff {
						tempstr += v
						tempstr += "\r\n"
					}
				}
				tempstr += "流过滤器组定义了"
				tempstr += strconv.Itoa(len(flowlname))
				tempstr += "个，"
				diff = diffstr(flowlname, flownameofrule)
				if len(diff) == 0 {
					tempstr += "定义的流过滤器组全部被rule规则引用。\r\n"
				} else {
					tempstr += "其中以下流过滤器组定义了但未被rule规则引用:\r\n"
					for _, v := range diff {
						tempstr += v
						tempstr += "\r\n"
					}
				}

				tempstr += "rule规则定义了"
				for k, _ := range v.Rule {
					rulename = append(rulename, k)
				}
				for _, vv := range v.Rulebindup {
					for _, vvv := range vv {
						rulenameofbind = append(rulenameofbind, vvv)
					}
				}
				tempstr += strconv.Itoa(len(rulename))
				tempstr += "个，"
				diff = diffstr(rulename, rulenameofbind)
				if len(diff) == 0 {
					tempstr += "定义的rule规则全部被绑定到用户模版。\r\n"
				} else {
					tempstr += "其中以下rule规则定义了但未被绑定:\r\n"
					for _, v := range diff {
						tempstr += v
						tempstr += "\r\n"
					}
				}

				tempstr += "非本地用户模版定义了"
				var prergprofile []string
				for _, vv := range v.Userprofile[0] {
					userprofile = append(userprofile, vv)
					prergprofile = append(prergprofile, vv)
				}
				for _, vv := range v.Userprofile[1] {
					userprofile = append(userprofile, vv)
				}

				for _, vv := range v.Userprofile[2] {
					userprofile = append(userprofile, vv)
				}
				tempstr += strconv.Itoa(len(userprofile))
				tempstr += "个，本地用户模版定义了"
				var localuserprofile []string

				for _, vv := range v.Userprofile[3] {
					localuserprofile = append(localuserprofile, vv)
				}
				tempstr += strconv.Itoa(len(localuserprofile))
				tempstr += "个,用户模版组定义了"
				for _, vv := range v.Userprofileg {
					userprofileg = append(userprofileg, vv)
				}
				tempstr += strconv.Itoa(len(userprofileg))
				tempstr += "个\r\n"
				diff = jiaojistr(unionstr(userprofile, localuserprofile), userprofileg)
				if len(diff) == 0 {
					tempstr += "定义的用户模版组名称和用户模版没有冲突。\r\n"
				} else {
					tempstr += "其中以下用户模版名称和用户模版组名称重复定义:\r\n"
					for _, v := range diff {
						tempstr += v
						tempstr += "\r\n"
					}

				}
				var upbindinuserg []string
				for _, vv := range v.Upbindgroup {
					for _, vvv := range vv {
						if !ContainsString(upbindinuserg, vvv) {
							upbindinuserg = append(upbindinuserg, vvv)
						}
					}
				}
				diff = diffstr(upbindinuserg, unionstr(localuserprofile, prergprofile))
				if len(diff) == 0 {
					tempstr += "用户模版组名称中引用的upname用户模版名称正确。\r\n"
				} else {
					tempstr += "以下定义的用户模版组中引用的用户profile名称冲突:\r\n"
					for _, v := range diff {
						tempstr += v
						tempstr += "\r\n"
					}

				}

			}

		case "compare":
			log.Println(makenowstring() + " 配置文件读取完毕，开始比较配置结果" + handler.Filename + " ....")
			if len(vnfdata) < 2 {
				tempstr += "对比模式需要两个或两个以上同类型网元的对比，请核实上传的压缩文件"
				break
			}
			allkey := []string{}
			for i, _ := range vnfdata {
				for k, _ := range vnfdata[i].Commconfig {
					if !ContainsString(allkey, k) {
						allkey = append(allkey, k)
					}
					continue
				}
			}
			tempstr += "<html><head>差异结果</head><style type=\"text/css\">" +
				"table, th, td {" +
				"border: 1px solid black;" +
				"border-collapse: collapse;" +
				"table{table-layout: fixed;}" +
				"td{word-break:break-all;word-wrap:break-word;}" +
				"}</style><body><table style=\"width:100%\"><tr><th></th>"
			for i, _ := range vnfdata {
				tempstr += "<th>"
				tempstr += vnfdata[i].Vnfname
				tempstr += "</th>"
			}
			tempstr += "</tr>"
			configdata := make([][]string, len(vnfdata))
			for _, key := range allkey {
				same := true
				ok := true
				jjstr := []string{}
				for i, _ := range vnfdata {
					configdata[i], ok = vnfdata[i].Commconfig[key]
					if !ok {
						same = false
						configdata[i] = []string{"无此配置"}
					}
				}

				for i, v := range configdata {
					if same && i < (len(configdata)-1) {
						jjstr = jiaojistr(v, configdata[i+1])
					}
				}
				if len(jjstr) == 0 {
					same = false
				} else {
					for i, v := range configdata {
						configdata[i] = diffstr(v, jjstr)
						if len(configdata[i]) > 0 {
							same = false
						}
					}
				}

				if !same {
					tempstr += "<tr><td>" + key + "</td>"
					for _, v := range configdata {
						tempstr += "<td>"
						tempstr += strings.Join(v, "<br>")
						tempstr += "</td>"
					}
					tempstr += "</tr>"
				}

			}
			/*
				for _, key := range allkey {

					r1, ok1 := vnfdata[0].Commconfig[key]
					r2, ok2 := vnfdata[1].Commconfig[key]
					if !ok1 || !ok2 {
						tempstr += "<tr><td>" + key + "</td>"
						if ok1 {
							tempstr += "<td>"
							for _, v := range r1 {
								tempstr += v
							}
							tempstr += "</td>"
							tempstr += "<td>无此配置</td></tr>"
						}
						if ok2 {
							tempstr += "<td>无此配置</td><td>"
							for _, v := range r2 {
								tempstr += v
							}
							tempstr += "</td></tr>"
						}
						continue
					}
					jjstr := jiaojistr(r1, r2)
					diff1 := diffstr(r1, jjstr)
					diff2 := diffstr(r2, jjstr)
					if len(jjstr) > 0 && len(diff1) == 0 && len(diff2) == 0 {
						/*	tempstr += ("<tr><td>same:" + key + "</td>")
							tempstr += "<td>" + strings.Join(r1, "<br>") + "</td>"
							tempstr += "<td>" + strings.Join(r2, "<br>") + "</td>"
							tempstr += "</tr>"
						continue
					} else {
						tempstr += ("<tr><td>" + key + "</td>")
						tempstr += "<td>" + strings.Join(diff1, "<br>") + "</td>"
						tempstr += "<td>" + strings.Join(diff2, "<br>") + "</td>"
						tempstr += "</tr>"

						continue
					}


				}
			*/
			tempstr += "</table></body></html>"
		}
		w.Write([]byte(tempstr))

	default:
		return
	}
}


