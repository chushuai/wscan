/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package reverse

import (
	"bytes"
	"encoding/json"
	"fmt"
	"golang.org/x/net/context"
	"sync"
	"time"
	"wscan/core/http"
	"wscan/core/utils"
	"wscan/core/utils/log"
)

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

func NewReverse(config *Config) *Reverse {
	r := &Reverse{config: config,
		db: &DB{},
	}
	if config.HTTPServerConfig.Enabled == true {
		r.reverseHTTPServer = NewHTTPServer(config)
	} else {
		return nil
	}
	if config.DNSServerConfig.Enabled == true {
		if config.DNSServerConfig.Domain == "" {
			log.Fatal("Please specify the DNSLOG first level domain name")
		}
		if ds, err := NewDNSServer(config, r.db); err == nil {
			r.reverseDNSServer = ds
		}
	}
	if r.config.RMIServerConfig.Enabled == true {
		r.reverseRMIServer = NewRMIServer(config, r.db)
	}
	return r
}

func (r *Reverse) Start() {
	wg := sync.WaitGroup{}
	if r.config.HTTPServerConfig.Enabled == true {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r.reverseHTTPServer.Start()
		}()
	}
	if r.config.DNSServerConfig.Enabled == true {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r.reverseDNSServer.Start()
		}()
	}

	if r.config.RMIServerConfig.Enabled == true {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r.reverseRMIServer.Start()
		}()
	}
	time.Sleep(1 * time.Second)
	wg.Wait()
}

func (r *Reverse) Close() error {
	return nil
}

func (r *Reverse) Config() *Config {
	return r.config
}

var D DnsInfo
var DnsData = make(map[string][]DnsInfo)

var DnsDataRwLock sync.RWMutex

type DnsInfo struct {
	Type      string
	Subdomain string
	Ipaddress string
	Time      int64
}

func (d *DnsInfo) Set(userDir string, data DnsInfo) {
	DnsDataRwLock.Lock()
	defer DnsDataRwLock.Unlock()
	if DnsData[userDir] == nil {
		DnsData[userDir] = []DnsInfo{data}
	} else {
		DnsData[userDir] = append(DnsData[userDir], data)
	}
}

func (d *DnsInfo) Get(userDir string) string {
	DnsDataRwLock.RLock()
	defer DnsDataRwLock.RUnlock()
	res := ""
	if DnsData[userDir] != nil {
		v, _ := json.Marshal(DnsData[userDir])
		res = string(v)
	}
	if res == "" {
		res = "null"
	}
	return res
}

func (d *DnsInfo) Clear(userDir string) {
	DnsData[userDir] = []DnsInfo{}
	DnsData["other"] = []DnsInfo{}
}

func CheckReverse(config *Config, query string, typ string, timeout int64) bool {
	// 构建请求体
	body := QueryInfo{Query: query}
	requestBody, err := json.Marshal(body)
	if err != nil {
		log.Infof("Failed to marshal request body:", err)
		return false
	}

	httpBaseURL := config.ClientConfig.HTTPBaseURL
	if httpBaseURL == "" {
		return false
	}
	relativePath := "/api/verifyHttp"
	if typ == "dns" {
		relativePath = "/api/verifyDns"
	}

	startTime := time.Now()
	for {

		// 发送POST请求
		req, err := http.NewRequest("POST", utils.UrlJoinPath(httpBaseURL, relativePath), bytes.NewBuffer(requestBody))
		if err != nil {
			fmt.Println("Failed to send HTTP request:", err)
			return false
		}
		req.SetHeader("token", config.Token)
		req.SetValue("Content-Type", "application/json")

		client := http.NewClient()
		resp, err := client.DoRaw(req)
		if err != nil {
			fmt.Println(err)
			return false
		}
		rd := RespData{}
		err = json.Unmarshal([]byte(resp.Text), &rd)
		if err == nil && rd.Msg == "true" {
			return true
		}

		if time.Since(startTime).Seconds() > float64(timeout) {
			break
		}
		time.Sleep(2 * time.Second)
	}
	return false
}
