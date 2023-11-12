/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package reverse

import (
	"github.com/miekg/dns"
	"go.etcd.io/bbolt"
	"golang.org/x/net/context"
	"io"
	"net"
	"net/http"
	"sync"
	"time"
)

type DB struct {
	sync.Mutex
	path     string
	isTempDB bool
	*bbolt.DB
}

type DNSServer struct {
	*dns.Server
	config                *Config
	db                    *DB
	internalGroupEventMap *sync.Map
}

type HTTPServer struct {
	Server *http.Server
	//Router                *httprouter.Router
	config                *Config
	db                    *DB
	internalGroupEventMap *sync.Map
}

type RMIServer struct {
	listener              net.Listener
	config                *Config
	db                    *DB
	internalGroupEventMap *sync.Map
}

type Reverse struct {
	ctx                   context.Context
	cancel                func()
	config                *Config
	db                    *DB
	reverseHTTPServer     *HTTPServer
	reverseDNSServer      *DNSServer
	reverseRMIServer      *RMIServer
	groupUnitCallbackMap  sync.Map
	internalGroupEventMap *sync.Map
	groupToDelete         remoteFetchEventRequest
}

type Unit struct {
	sync.Mutex
	// reverse *<nil>
	id string
	// group *<nil>
	Callback func(*Event) error
	Data     interface {
	}
}

type UnitGroup struct {
	id             string
	units          sync.Map
	callbackCalled int32
	expireAt       time.Time
}

type peekedConn struct {
	net.Conn
	r io.Reader
}

type rmiHTTPListener struct {
	net.Listener
	token                 string
	db                    *DB
	internalGroupEventMap *sync.Map
}
