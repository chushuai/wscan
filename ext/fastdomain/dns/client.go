/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package dns

import (
	"crypto/tls"
	"github.com/miekg/dns"
	"net"
	"sync"
)

type Client struct {
	Net            string
	UDPSize        uint16
	TLSConfig      *tls.Config
	Dialer         *net.Dialer
	Timeout        int64
	DialTimeout    int64
	ReadTimeout    int64
	WriteTimeout   int64
	TsigSecret     map[string]string
	TsigProvider   dns.TsigProvider
	SingleInflight bool
	group          singleflight
}

type call struct {
	wg   sync.WaitGroup
	val  *dns.Msg
	rtt  int64
	err  error
	dups int
}

type singleflight struct {
	sync.Mutex
	m                    map[string]*call
	dontDeleteForTesting bool
}
