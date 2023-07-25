// vercel serverless function DOES NOT support websocket,it is just a test,not working
package handler

import (
	"bytes"
	"context"
	"encoding/binary"
	"io"
	"log"
	"net"
	"net/http"
	"strconv"

	"github.com/google/uuid"
	"github.com/zhujq/websocket"
)

const port = "80"

var (
	rsp_version = []byte{0x00, 0x00}
)

func BytesCombine(pBytes ...[]byte) []byte {
	var buffer bytes.Buffer
	for index := 0; index < len(pBytes); index++ {
		buffer.Write(pBytes[index])
	}
	return buffer.Bytes()
}

func Handler(w http.ResponseWriter, r *http.Request) {
	ao := &websocket.AcceptOptions{InsecureSkipVerify: true}
	conn, err := websocket.Accept(w, r, ao)
	if err != nil {
		log.Println("webscoket accept err：", err)
		return
	}
	defer conn.Close(websocket.StatusInternalError, "inner error！")
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()

	b := [1024]byte{0x0}
	netconn := websocket.NetConn(ctx, conn, websocket.MessageBinary)
	n, err := netconn.Read(b[:])

	if n < 24 {
		log.Println("Err length of less head")
		return
	}
	if err != nil {
		log.Println("Error reading from websocket conn,error is: ", err)
		return
	}

	if b[0] != 0x00 {
		netconn.Close()
		log.Println("Wrong vless version")
		return
	}
	uuid, err := uuid.FromBytes(b[1:17])
	if err != nil {
		log.Println("Error get uuid,error is: ", err)
		return
	}
	if uuid.String() != "b831381d-6324-4d53-ad4f-8cda48b30811" {
		log.Println("Error uuid")
		return
	}
	//	log.Println("uuid is:" + uuid.String())
	adlen := int(b[17])
	cmd := int(b[18+adlen])
	if cmd != 1 {
		log.Println("Only support TCP")
		return
	}

	var port uint16
	binary.Read(bytes.NewReader(b[(19+adlen):(21+adlen)]), binary.BigEndian, &port)

	addtype := int(b[21+adlen])

	host := ""
	hostlen := 0
	nIndex := 0
	switch addtype {
	case 1:
		host = net.IPv4(b[22+adlen], b[23+adlen], b[24+adlen], b[25+adlen]).String()
		hostlen = 4
		nIndex = 25 + adlen
	case 2:
		hostlen = int(b[(22 + adlen)])
		host = string(b[(23 + adlen):(23 + adlen + hostlen)])
		nIndex = 23 + adlen + hostlen
	case 3:
		hostlen = 16
		host = net.IP{b[22+adlen], b[23+adlen], b[24+adlen], b[25+adlen], b[26+adlen], b[27+adlen], b[28+adlen], b[29+adlen], b[30+adlen], b[31+adlen], b[32+adlen], b[33+adlen], b[34+adlen], b[35+adlen], b[36+adlen], b[37+adlen]}.String()
		nIndex = 37 + adlen
	}
	log.Println(host + ":" + strconv.Itoa(int(port)))

	server, err := net.Dial("tcp", host+":"+strconv.Itoa(int(port)))
	if server != nil {
		defer server.Close()
	}
	if err != nil {
		log.Println("error to connect destination server,error is:", err)
		return
	}
	_, err = server.Write(b[nIndex:n])
	if err != nil {
		log.Println("error to write packet to destination server,error is:", err)
		return
	}

	var buff []byte
	_, err = server.Read(buff)
	if err != nil {
		log.Println("error to read packet from destination server,error is:", err)
		return
	}

	netconn.Write(rsp_version)
	go io.Copy(server, netconn)
	io.Copy(netconn, server)

	return

}
