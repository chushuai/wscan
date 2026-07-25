/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package reverse

import (
	"bytes"
	"time"
	logger "wscan/core/utils/log"

	"net"
	"sync"
)

type RMIServer struct {
	listener              net.Listener
	config                *Config
	db                    *DB
	internalGroupEventMap *sync.Map
}

//	func (*RMIServer) Accept() (net.Conn, error) {
//		return nil, nil
//	}
//
//	func (*RMIServer) Addr() net.Addr {
//		return nil
//	}
func (r *RMIServer) Close() error {
	if r.listener != nil {
		return r.listener.Close()
	}
	return nil
}

func (r *RMIServer) Start() {
	// RMI connections are handled via the Listener protocol multiplexer in conn.go.
	// The HTTP listener accepts all TCP connections and routes RMI traffic
	// (detected by JRMI magic bytes) to RMIServer.Handle() via NewListener.
	// No separate listener is needed here.
}

func NewRMIServer(config *Config, internalGroupEventMap *sync.Map, db *DB) *RMIServer {
	return &RMIServer{config: config,
		db:                    db,
		internalGroupEventMap: internalGroupEventMap,
	}
}

func handleRMIConn() {

}

func rmiServerCheckAndPrepare() {

}

func (s *RMIServer) Handle(conn *PeekConn) {
	defer conn.Close()
	buf := make([]byte, 1024)
	_, err := (*conn).Read(buf)
	if err != nil {
		logger.Warnf("[jndi] accept data reading err:%s", err)
		return
	}
	// RMI Protocol
	if checkRMI(buf) {
		_, _ = (*conn).Write(rmireplay)
		// 这里读到的数据没有用处
		_, _ = (*conn).Read(buf)
		// 需要发一次空数据然后接收call信息
		_, _ = (*conn).Write([]byte{})
		_, _ = (*conn).Read(buf)

		var dataList []byte
		var flag bool
		// 从后往前读因为空都是00
		for i := len(buf) - 1; i >= 0; i-- {
			// 这里要用一个flag来区分
			// 因为正常数据中也会含有00
			if buf[i] != 0x00 || flag {
				flag = true
				dataList = append(dataList, buf[i])
			}
		}
		// 已读到的长度等于当前读到的字节代表的数字
		// 那么认为已读到的字符串翻转后是路径参数
		var j_ int
		for i := 0; i < len(dataList); i++ {
			if int(dataList[i]) == i {
				j_ = i
				break
			}
		}

		if len(dataList) < j_ {
			return
		}
		temp := dataList[0:j_]
		pathBytes := &bytes.Buffer{}
		// 翻转后拿到真正的路径参数
		for i := len(temp) - 1; i >= 0; i-- {
			pathBytes.Write([]byte{dataList[i]})
		}
		path := pathBytes.String()

		hashedToken, groupID, unitID, _, err := parsePath(path)
		if err != nil {
			return
		}
		if generateHashedToken(s.config.Token, groupID, unitID) == hashedToken {
			ev := &Event{
				GroupID:     groupID,
				UnitID:      unitID,
				EventType:   "rmi",
				EventSource: "public",
				Request:     "",
				RemoteAddr:  conn.RemoteAddr().String(),
				TimeStamp:   time.Now().UnixMilli(),
			}
			s.db.storeEvent(ev)
			s.internalGroupEventMap.Store(groupID, ev)
		}
	}
}

//	func (j *RMIServer) getSubPath(s string) string {
//		i := strings.Index(strings.TrimLeft(s, "/"), "/")
//		if i <= 0 {
//			return ""
//		}
//		return s[:i]
//	}
var (
	ldapfinger = "300c020101600702010304008000"
	ldapreply  = []byte{
		0x30, 0x0c,
		0x02, 0x01, 0x01,
		0x61, 0x07,
		0x0a, 0x01, 0x00,
		0x04, 0x00,
		0x04, 0x00,
	}
)

func ldapPathLength(buf []byte) int {
	if len(buf) < 9 {
		return 0
	}
	length := buf[8]
	if len(buf) < 9+int(length) {
		return 0
	}
	return int(length)
}

var (

	// https://docs.oracle.com/javase/9/docs/specs/rmi/protocol.html
	rmireplay = []byte{
		0x4e, 0x00, 0x09, // 保证4e00开头
		0x31, 0x32, 0x37, 0x2e, 0x30, 0x2e, 0x30, 0x2e, 0x31, // 模拟 127.0.0.1
		0x00, 0x00, 0xc4, 0x12,
	}
)

func checkRMI(data []byte) bool {
	if len(data) < 8 {
		return false
	}
	// header
	if data[0] == 0x4a &&
		data[1] == 0x52 &&
		data[2] == 0x4d &&
		data[3] == 0x49 {
		// version
		if data[4] != 0x00 {
			return false
		}
		if data[5] != 0x01 &&
			data[5] != 0x02 {
			return false
		}

		// protocol
		if data[6] != 0x4b &&
			data[6] != 0x4c &&
			data[6] != 0x4d {
			return false
		}
		lastData := data[7:]
		for _, v := range lastData {
			if v != 0x00 {
				return false
			}
		}
		return true
	}

	return false
}
