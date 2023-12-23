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

type queryInfo struct {
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

func (self *HTTPServer) GetUser(domain string) string {
	user := "admin"
	//for i, v := range Config.HTTP.User {
	//	if strings.Contains(domain, v) {
	//		user = i
	//		break
	//	}
	//}
	return user
}

func index(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/template", http.StatusMovedPermanently)
}

func (self *HTTPServer) GetDnsData(w http.ResponseWriter, r *http.Request) {
	key := r.Header.Get("token")
	if self.VerifyToken(key) {
		fmt.Fprint(w, JsonRespData(RespData{
			HTTPStatusCode: "200",
			Msg:            D.Get(key),
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
		D.Clear(key)
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
	var Q queryInfo
	key := r.Header.Get("token")
	if self.VerifyToken(key) {
		body, _ := io.ReadAll(r.Body)
		json.Unmarshal(body, &Q)
		resp := RespData{
			HTTPStatusCode: "200",
			Msg:            "false",
		}
		for _, v := range DnsData[key] {
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
	var Q queryInfo
	key := r.Header.Get("token")
	if self.VerifyToken(key) {
		body, _ := io.ReadAll(r.Body)
		json.Unmarshal(body, &Q)
		resp := RespData{
			HTTPStatusCode: "200",
			Msg:            "false",
		}
		for _, v := range DnsData[key] {
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
		for _, v := range DnsData[key] {
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
		for _, v := range DnsData[key] {
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
	user := self.GetUser(r.URL.Path)
	clientIp := r.RemoteAddr
	xip := r.Header.Get("X-Forwarded-For")
	if xip != "" && isIpaddress(xip) {
		clientIp = xip
	}
	D.Set(user, DnsInfo{
		Type:      "HTTP",
		Subdomain: r.URL.Path,
		Ipaddress: clientIp,
		Time:      time.Now().Unix(),
	})
}

//go:embed template
var template embed.FS

func (self *HTTPServer) Start() {
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
	mux.HandleFunc("/"+"dnslog"+"/", self.HttpRequestLog)
	server := &http.Server{
		Addr:    ":" + self.config.HTTPServerConfig.ListenPort,
		Handler: mux,
	}
	logger.Info("Http address: http://" + "0.0.0.0:" + self.config.HTTPServerConfig.ListenPort)
	if err := server.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}

func NewHTTPServer(cfg *Config) *HTTPServer {
	return &HTTPServer{
		config: cfg,
	}
}
