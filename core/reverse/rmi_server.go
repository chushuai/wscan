/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package reverse

import (
	"net"
	"sync"
)

type RMIServer struct {
	listener              net.Listener
	config                *Config
	db                    *DB
	internalGroupEventMap *sync.Map
}

type rmiHTTPListener struct {
	net.Listener
	token                 string
	db                    *DB
	internalGroupEventMap *sync.Map
}
