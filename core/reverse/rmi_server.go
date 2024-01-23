/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package reverse

import (
	"bytes"
	"fmt"
	"time"
	"wscan/core/utils"
	logger "wscan/core/utils/log"

	"github.com/sirupsen/logrus"
	"net"
	"strings"
	"sync"
)

type RMIServer struct {
	listener              net.Listener
	config                *Config
	db                    *DB
	internalGroupEventMap *sync.Map
}

func NewRMIServer(config *Config, db *DB) *RMIServer {
	return &RMIServer{
		config: config,
		db:     db,
	}
}

func (*RMIServer) Accept() (net.Conn, error) {
	return nil, nil
}

func (*RMIServer) Addr() net.Addr {
	return nil
}

func (r *RMIServer) Close() error {
	r.Close()
	return nil
}

func (r *RMIServer) Start() {
	var err error
	if r.config.RMIServerConfig.ListenPort == "" {
		if _, port, err := utils.GetRandomLocalAddr(); err == nil {
			r.config.RMIServerConfig.ListenPort = fmt.Sprintf("%d", port)
		}
	}
	address := net.JoinHostPort(r.config.RMIServerConfig.ListenIP, r.config.RMIServerConfig.ListenPort)
	r.listener, err = net.Listen("tcp", address)
	if err != nil {
		logger.Warnf("[jndi] listen fail err:%s", err)
		return
	}
	logger.Infof("reverse server rmi/jndi: %s", address)
	for {
		conn, err := r.listener.Accept()
		if err != nil {
			logger.Warnf("[jndi] listen accept fail err:%s", err)
			break
		}
		go r.Handle(&conn)
	}
}

func (r *RMIServer) Handle(conn *net.Conn) {
	defer func() {
		(*conn).Close()
	}()

	buf := make([]byte, 1024)
	num, err := (*conn).Read(buf)
	if err != nil {
		logrus.Warnf("[jndi] accept data reading err:%s", err)
		return
	}
	var sid string
	hexStr := fmt.Sprintf("%x", buf[:num])
	// LDAP Protocol
	if hexStr == ldapfinger {
		if _, err = (*conn).Write(ldapreply); err == nil {
			_, err = (*conn).Read(buf)
			if err != nil {
				logrus.Warnf("[jndi][ldap] read path data err:%s", err)
				return
			}
		}
		length := ldapPathLength(buf)
		pathBytes := bytes.Buffer{}
		for i := 1; i <= length; i++ {
			temp := []byte{buf[8+i]}
			pathBytes.Write(temp)
		}

		path := pathBytes.String()
		sid = r.getSubPath(path)
		// userDir := r.config.GetUserDir(r.config.Token)
		if sid != "" {
			D.Set(r.config.GetUserDir(r.config.Token), DnsInfo{
				Type:      "LDAP",
				Subdomain: path,
				Ipaddress: (*conn).RemoteAddr().String(),
				Time:      time.Now().Unix(),
			})
		}
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
		sid = r.getSubPath(path)
		if sid != "" {
			D.Set(r.config.GetUserDir(r.config.Token), DnsInfo{
				Type:      "RMI",
				Subdomain: path,
				Ipaddress: (*conn).RemoteAddr().String(),
				Time:      time.Now().Unix(),
			})
		}
	}
}

func (j *RMIServer) getSubPath(s string) string {
	i := strings.Index(strings.TrimLeft(s, "/"), "/")
	if i <= 0 {
		return ""
	}
	return s[:i]
}

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
