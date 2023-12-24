/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package reverse

import (
	"embed"
	"encoding/json"
	"fmt"
	"github.com/julienschmidt/httprouter"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"time"
	"wscan/core/utils"
	logger "wscan/core/utils/log"
)

type HTTPServer struct {
	Server                *http.Server
	Router                *httprouter.Router
	config                *Config
	db                    *DB
	internalGroupEventMap *sync.Map
}

type RespData struct {
	HTTPStatusCode string
	Msg            string
}

type BulkRespData struct {
	HTTPStatusCode string
	Msg            []string
}

type QueryInfo struct {
	Query string
}

func JsonRespData(resp interface{}) string {
	rs, err := json.Marshal(resp)
	if err != nil {
		log.Fatalln(err)
	}
	return string(rs)
}

func (self *HTTPServer) VerifyToken(token string) bool {
	flag := false
	if token == self.config.Token {
		flag = true
	}
	return flag
}

func index(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/template", http.StatusMovedPermanently)
}

func (self *HTTPServer) GetDnsData(w http.ResponseWriter, r *http.Request) {
	key := r.Header.Get("token")
	if self.VerifyToken(key) {
		userDir := self.config.GetUserDir(key)
		fmt.Fprint(w, JsonRespData(RespData{
			HTTPStatusCode: "200",
			Msg:            D.Get(userDir),
		}))
	} else {
		fmt.Fprint(w, JsonRespData(RespData{
			HTTPStatusCode: "403",
			Msg:            "false",
		}))
	}
}

func (self *HTTPServer) verifyTokenApi(w http.ResponseWriter, r *http.Request) {
	var data map[string]string
	token, _ := io.ReadAll(r.Body)
	json.Unmarshal(token, &data)
	if self.VerifyToken(data["token"]) {
		fmt.Fprint(w, JsonRespData(RespData{
			HTTPStatusCode: "200",
			Msg:            "dnslog.demon.cn", //Core.Config.HTTP.User[data["token"]] + "." + Core.Config.DNS.Domain,
		}))
	} else {
		fmt.Fprint(w, JsonRespData(RespData{
			HTTPStatusCode: "403",
			Msg:            "false",
		}))
	}
}

func (self *HTTPServer) JsonRespData(resp interface{}) string {
	rs, err := json.Marshal(resp)
	if err != nil {
		log.Fatalln(err)
	}
	return string(rs)
}

func (self *HTTPServer) Clean(w http.ResponseWriter, r *http.Request) {
	key := r.Header.Get("token")
	if self.VerifyToken(key) {
		D.Clear(self.config.GetUserDir(key))
		fmt.Fprint(w, JsonRespData(RespData{
			HTTPStatusCode: "200",
			Msg:            "success",
		}))
	} else {
		fmt.Fprint(w, JsonRespData(RespData{
			HTTPStatusCode: "403",
			Msg:            "false",
		}))
	}
}

func (self *HTTPServer) verifyDns(w http.ResponseWriter, r *http.Request) {
	DnsDataRwLock.RLock()
	defer DnsDataRwLock.RUnlock()
	var Q QueryInfo
	key := r.Header.Get("token")
	if self.VerifyToken(key) {
		body, _ := io.ReadAll(r.Body)
		json.Unmarshal(body, &Q)
		resp := RespData{
			HTTPStatusCode: "200",
			Msg:            "false",
		}
		userDir := self.config.GetUserDir(key)
		for _, v := range DnsData[userDir] {
			if v.Subdomain == Q.Query {
				resp.Msg = "true"
				break
			}

		}
		fmt.Fprint(w, JsonRespData(resp))
	} else {
		fmt.Fprint(w, JsonRespData(RespData{
			HTTPStatusCode: "403",
			Msg:            "false",
		}))
	}
}

func (self *HTTPServer) verifyHttp(w http.ResponseWriter, r *http.Request) {
	DnsDataRwLock.RLock()
	defer DnsDataRwLock.RUnlock()
	var Q QueryInfo
	key := r.Header.Get("token")
	if self.VerifyToken(key) {
		body, _ := io.ReadAll(r.Body)
		json.Unmarshal(body, &Q)
		resp := RespData{
			HTTPStatusCode: "200",
			Msg:            "false",
		}
		userDir := self.config.GetUserDir(key)
		for _, v := range DnsData[userDir] {
			if v.Subdomain == Q.Query && v.Type == "HTTP" {
				resp.Msg = "true"
				break
			}

		}
		fmt.Fprint(w, JsonRespData(resp))
	} else {
		fmt.Fprint(w, JsonRespData(RespData{
			HTTPStatusCode: "403",
			Msg:            "false",
		}))
	}
}

func (self *HTTPServer) BulkVerifyDns(w http.ResponseWriter, r *http.Request) {
	DnsDataRwLock.RLock()
	defer DnsDataRwLock.RUnlock()
	var Q []string
	key := r.Header.Get("token")
	if self.VerifyToken(key) {
		body, _ := io.ReadAll(r.Body)
		json.Unmarshal(body, &Q)
		var result []string
		userDir := self.config.GetUserDir(key)
		for _, v := range DnsData[userDir] {
			for _, q := range Q {
				if v.Subdomain == q {
					result = append(result, q)
				}
			}
		}
		var resp BulkRespData
		if len(result) == 0 {
			resp = BulkRespData{
				HTTPStatusCode: "200",
				Msg:            result,
			}
		} else {
			resp = BulkRespData{
				HTTPStatusCode: "200",
				Msg:            removeDuplication(result),
			}
		}
		fmt.Fprint(w, JsonRespData(resp))
	} else {
		fmt.Fprint(w, JsonRespData(RespData{
			HTTPStatusCode: "403",
			Msg:            "false",
		}))
	}
}

func removeDuplication(arr []string) []string {
	if arr == nil || len(arr) == 0 {
		return []string{}
	}
	j := 0
	for i := 1; i < len(arr); i++ {
		if arr[i] == arr[j] {
			continue
		}
		j++
		arr[j] = arr[i]
	}
	return arr[:j+1]
}

func (self *HTTPServer) BulkVerifyHttp(w http.ResponseWriter, r *http.Request) {
	DnsDataRwLock.RLock()
	defer DnsDataRwLock.RUnlock()
	var Q []string
	key := r.Header.Get("token")
	if self.VerifyToken(key) {
		body, _ := io.ReadAll(r.Body)
		json.Unmarshal(body, &Q)
		var result []string
		userDir := self.config.GetUserDir(key)
		for _, v := range DnsData[userDir] {
			for _, q := range Q {
				if v.Subdomain == q && v.Type == "HTTP" {
					result = append(result, q)
				}
			}
		}
		var resp BulkRespData
		if len(result) == 0 {
			resp = BulkRespData{
				HTTPStatusCode: "200",
				Msg:            result,
			}
		} else {
			resp = BulkRespData{
				HTTPStatusCode: "200",
				Msg:            removeDuplication(result),
			}
		}
		fmt.Fprint(w, JsonRespData(resp))
	} else {
		fmt.Fprint(w, JsonRespData(RespData{
			HTTPStatusCode: "403",
			Msg:            "false",
		}))
	}
}

func (self *HTTPServer) removeDuplication(arr []string) []string {
	if arr == nil || len(arr) == 0 {
		return []string{}
	}
	j := 0
	for i := 1; i < len(arr); i++ {
		if arr[i] == arr[j] {
			continue
		}
		j++
		arr[j] = arr[i]
	}
	return arr[:j+1]
}

func (self *HTTPServer) isIpaddress(ip string) bool {
	return net.ParseIP(ip) != nil
}

func isIpaddress(ip string) bool {
	return net.ParseIP(ip) != nil
}

func (self *HTTPServer) HttpRequestLog(w http.ResponseWriter, r *http.Request) {
	clientIp := r.RemoteAddr
	xip := r.Header.Get("X-Forwarded-For")
	if xip != "" && isIpaddress(xip) {
		clientIp = xip
	}
	D.Set(self.config.GetUserDir(self.config.Token), DnsInfo{
		Type:      "HTTP",
		Subdomain: r.URL.Path,
		Ipaddress: clientIp,
		Time:      time.Now().Unix(),
	})
}

//go:embed template
var template embed.FS

func (self *HTTPServer) Start() {
	if self.config.HTTPServerConfig.Enabled == false {
		logger.Fatal("http server is not enabled")
	}
	if self.config.Token == "" {
		logger.Fatalf(" you must set Token in config file, for example: %s", utils.RandLetters(8))
	}
	if self.config.HTTPServerConfig.ListenPort == "" {
		logger.Fatalf(" you must set listen_port, for example: %s", utils.RandInt(8000, 9000))
	}
	mux := http.NewServeMux()
	mux.Handle("/template/", http.FileServer(http.FS(template)))
	mux.HandleFunc("/", index)
	mux.HandleFunc("/api/verifyToken", self.verifyTokenApi)
	mux.HandleFunc("/api/getDnsData", self.GetDnsData)
	mux.HandleFunc("/api/Clean", self.Clean)
	mux.HandleFunc("/api/verifyDns", self.verifyDns)
	mux.HandleFunc("/api/bulkVerifyDns", self.BulkVerifyDns)
	mux.HandleFunc("/api/verifyHttp", self.verifyHttp)
	mux.HandleFunc("/api/BulkVerifyHttp", self.BulkVerifyHttp)
	mux.HandleFunc("/"+self.config.GetUserDir(self.config.Token)+"/", self.HttpRequestLog)
	server := &http.Server{
		Addr:    ":" + self.config.HTTPServerConfig.ListenPort,
		Handler: mux,
	}
	logger.Infof("reverse server url: http://%s:%s, token:%s", self.config.HTTPServerConfig.ListenIP,
		self.config.HTTPServerConfig.ListenPort, self.config.Token)
	logger.Infof("reverse user dir: http://%s:%s/%s/", self.config.HTTPServerConfig.ListenIP,
		self.config.HTTPServerConfig.ListenPort, self.config.GetUserDir(self.config.Token))
	if err := server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

func NewHTTPServer(cfg *Config) *HTTPServer {
	return &HTTPServer{
		config: cfg,
	}
}
