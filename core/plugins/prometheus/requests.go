/**
2 * @Author: shaochuyu
3 * @Date: 6/25/23
4 */

package prometheus

import (
	"bytes"
	"compress/gzip"
	"crypto/tls"
	"github.com/pkg/errors"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptrace"
	"net/http/httputil"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
	"wscan/core/model"
)

var (
	Client           *http.Client
	ClientNoRedirect *http.Client
	DialTimout       = 5 * time.Second
	KeepAlive        = 15 * time.Second

	urlTypePool = sync.Pool{
		New: func() any {
			return new(model.UrlType)
		},
	}
	connectInfoTypePool = sync.Pool{
		New: func() any {
			return new(model.ConnInfoType)
		},
	}
	addrTypePool = sync.Pool{
		New: func() any {
			return new(model.AddrType)
		},
	}
	tracePool = sync.Pool{
		New: func() any {
			return new(httptrace.ClientTrace)
		},
	}

	requestPool = sync.Pool{
		New: func() any {
			return new(model.Request)
		},
	}
	responsePool = sync.Pool{
		New: func() any {
			return new(model.Response)
		},
	}
	httpBodyBufPool = sync.Pool{
		New: func() any {
			return make([]byte, 1024)
		},
	}
	httpBodyPool = sync.Pool{
		New: func() any {
			return make([]byte, 4096)
		},
	}
)

func InitHttpClient(ThreadsNum int, DownProxy string, Timeout time.Duration) error {
	dialer := &net.Dialer{
		Timeout:   DialTimout,
		KeepAlive: KeepAlive,
	}

	tr := &http.Transport{
		DialContext:         dialer.DialContext,
		MaxIdleConns:        1000,
		MaxIdleConnsPerHost: ThreadsNum * 2,
		IdleConnTimeout:     KeepAlive,
		TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
		TLSHandshakeTimeout: 5 * time.Second,
	}

	if DownProxy != "" {
		u, err := url.Parse(DownProxy)
		if err != nil {
			wrappedErr := errors.Errorf("Parse Proxy error: %v", err)
			return wrappedErr
		}
		tr.Proxy = http.ProxyURL(u)
	}

	clientCookieJar, _ := cookiejar.New(nil)
	clientNoRedirectCookieJar, _ := cookiejar.New(nil)

	Client = &http.Client{
		Transport: tr,
		Timeout:   Timeout,
		Jar:       clientCookieJar,
	}
	ClientNoRedirect = &http.Client{
		Transport: tr,
		Timeout:   Timeout,
		Jar:       clientNoRedirectCookieJar,
	}
	ClientNoRedirect.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

	return nil
}

func ParseUrl(u *url.URL) *model.UrlType {
	urlType := urlTypePool.Get().(*model.UrlType)

	urlType.Scheme = u.Scheme
	urlType.Domain = u.Hostname()
	urlType.Host = u.Host
	urlType.Port = u.Port()
	urlType.Path = u.Path
	urlType.Query = u.RawQuery
	urlType.Fragment = u.Fragment

	return urlType
}

func DoRequest(req *http.Request, redirect bool) (*http.Response, int64, error) {
	var (
		milliseconds int64
		oResp        *http.Response
		err          error
	)
	if req.Body == nil || req.Body == http.NoBody {
	} else {
		req.Header.Set("Content-Length", strconv.Itoa(int(req.ContentLength)))
		if req.Header.Get("Content-Type") == "" {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
	}
	start := time.Now()
	trace := tracePool.Get().(*httptrace.ClientTrace)
	trace.GotFirstResponseByte = func() {
		milliseconds = time.Since(start).Nanoseconds() / 1e6
	}

	req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace))

	if redirect {
		oResp, err = Client.Do(req)
	} else {
		oResp, err = ClientNoRedirect.Do(req)
	}

	if err != nil {
		wrappedErr := errors.Errorf("Request error: %v", err)
		return nil, 0, wrappedErr
	}

	return oResp, milliseconds, nil
}

func ParseHttpRequest(oReq *http.Request) (*model.Request, error) {
	var (
		req = requestPool.Get().(*model.Request)
	)

	req.Method = oReq.Method
	req.Url = ParseUrl(oReq.URL)

	headers := make(map[string]string)
	for k := range oReq.Header {
		headers[k] = oReq.Header.Get(k)
	}
	req.Headers = headers

	req.ContentType = oReq.Header.Get("Content-Type")
	if oReq.Body != nil && oReq.Body != http.NoBody {
		data, err := io.ReadAll(oReq.Body)
		if err != nil {
			wrappedErr := errors.Errorf("Get request error: %v", err)
			return nil, wrappedErr
		}
		req.Body = data
		oReq.Body = io.NopCloser(bytes.NewBuffer(data))
	}

	return req, nil
}

func ParseHttpResponse(oResp *http.Response, milliseconds int64) (*model.Response, error) {
	var (
		resp             = responsePool.Get().(*model.Response)
		err              error
		header           string
		rawHeaderBuilder strings.Builder
	)

	headers := make(map[string]string)
	resp.Status = int32(oResp.StatusCode)
	resp.Url = ParseUrl(oResp.Request.URL)

	for k := range oResp.Header {
		header = oResp.Header.Get(k)
		headers[k] = header

		rawHeaderBuilder.WriteString(k)
		rawHeaderBuilder.WriteString(": ")
		rawHeaderBuilder.WriteString(header)
		rawHeaderBuilder.WriteString("\n")
	}
	resp.Headers = headers
	resp.ContentType = oResp.Header.Get("Content-Type")
	// 原始请求头
	resp.RawHeader = []byte(strings.Trim(rawHeaderBuilder.String(), "\n"))

	// 原始http响应
	resp.Raw, err = httputil.DumpResponse(oResp, true)
	body, err := GetRespBody(oResp)
	if err != nil {
		return nil, err
	}

	if err != nil {
		resp.Raw = body
	}
	// http响应体
	resp.Body = body

	// 响应时间
	resp.Latency = milliseconds

	return resp, nil
}

func ParseTCPUDPRequest(content []byte) (*model.Request, error) {
	var (
		req = requestPool.Get().(*model.Request)
	)

	req.Raw = content

	return req, nil
}

func ParseTCPUDPResponse(content []byte, socket *net.Conn, transport string) (*model.Response, error) {
	var (
		resp       = responsePool.Get().(*model.Response)
		conn       = connectInfoTypePool.Get().(*model.ConnInfoType)
		connection = *socket

		addr     string
		addrType *model.AddrType
		addrList []string
		port     string
	)

	resp.Raw = content

	// source
	addr = connection.LocalAddr().String()
	addrList = strings.SplitN(addr, ":", 2)
	if len(addrList) == 2 {
		port = addrList[1]
	} else {
		port = ""
	}

	addrType = addrTypePool.Get().(*model.AddrType)
	addrType.Transport = transport
	addrType.Addr = addr
	addrType.Port = port
	conn.Source = addrType

	// destination
	addr = connection.RemoteAddr().String()
	addrList = strings.SplitN(addr, ":", 2)
	if len(addrList) == 2 {
		port = addrList[1]
	} else {
		port = ""
	}

	addrType = addrTypePool.Get().(*model.AddrType)
	addrType.Transport = transport
	addrType.Addr = addr
	addrType.Port = port
	conn.Source = addrType
	conn.Destination = addrType

	resp.Conn = conn

	return resp, nil
}

func GetRespBody(oResp *http.Response) ([]byte, error) {
	body := httpBodyPool.Get().([]byte)
	defer httpBodyPool.Put(body)

	if oResp.Header.Get("Content-Encoding") == "gzip" {
		gr, _ := gzip.NewReader(oResp.Body)
		defer gr.Close()
		for {
			buf := httpBodyBufPool.Get().([]byte)
			n, err := gr.Read(buf)
			if err != nil && err != io.EOF {
				return nil, err
			}
			if n == 0 {
				break
			}
			body = append(body, buf...)
			httpBodyBufPool.Put(buf)
		}
	} else {
		raw, err := io.ReadAll(oResp.Body)
		if err != nil {
			wrappedErr := errors.Errorf("Get response body error: %v", err)
			return nil, wrappedErr
		}
		body = raw
	}
	return body, nil
}

func PutUrlType(urlType *model.UrlType) {
	urlType.Scheme = ""
	urlType.Domain = ""
	urlType.Host = ""
	urlType.Port = ""
	urlType.Path = ""
	urlType.Query = ""
	urlType.Fragment = ""

	urlTypePool.Put(urlType)
}

func PutConnectInfo(connInfo *model.ConnInfoType) {
	connInfo.Source = nil
	connInfo.Destination = nil

	connectInfoTypePool.Put(connInfo)
}

func PutAddrType(addrType *model.AddrType) {
	addrType.Transport = ""
	addrType.Addr = ""

	addrTypePool.Put(addrType)
}

func PutRequest(request *model.Request) {
	request.Url = nil
	request.Method = ""
	request.Headers = nil
	request.ContentType = ""
	request.Body = nil
	request.Raw = nil
	request.RawHeader = nil
	request.Content = ""
	request.ReadTimeout = ""
	request.ConnectionId = ""

	requestPool.Put(request)
}
func PutResponse(response *model.Response) {
	response.Url = nil
	response.Status = 0
	response.Headers = nil
	response.ContentType = ""
	response.Body = nil
	response.Raw = nil
	response.RawHeader = nil
	response.Latency = 0
	response.Conn = nil

	responsePool.Put(response)
}

func init() {
	InitHttpClient(10, "", time.Duration(10)*time.Second)
}
