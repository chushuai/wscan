/**
2 * @Author: shaochuyu
3 * @Date: 3/14/24
4 */

package reverse

import (
	"bytes"
	"fmt"
	"github.com/sirupsen/logrus"
	"net"
	"sync"
	"time"
	logger "wscan/core/utils/log"
)

type LdapServer struct {
	listener              net.Listener
	config                *Config
	db                    *DB
	internalGroupEventMap *sync.Map
}

func (s *LdapServer) Handle(conn *PeekConn) {
	defer conn.Close()
	buf := make([]byte, 1024)
	num, err := (*conn).Read(buf)
	if err != nil {
		logger.Warnf("[ldap] accept data reading err:%s", err)
		return
	}

	hexStr := fmt.Sprintf("%x", buf[:num])
	// LDAP Protocol
	if hexStr == ldapfinger {
		if _, err = (*conn).Write(ldapreply); err == nil {
			_, err = (*conn).Read(buf)
			if err != nil {
				logrus.Warnf("[ldap] read path data err:%s", err)
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
		hashedToken, groupID, unitID, _, err := parsePath(path)
		if err != nil {
			return
		}
		if generateHashedToken(s.config.Token, groupID, unitID) == hashedToken {
			ev := &Event{
				GroupID:     groupID,
				UnitID:      unitID,
				EventType:   "ldap",
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

func NewLdapServer(config *Config, internalGroupEventMap *sync.Map, db *DB) *LdapServer {
	return &LdapServer{config: config,
		db:                    db,
		internalGroupEventMap: internalGroupEventMap,
	}
}
