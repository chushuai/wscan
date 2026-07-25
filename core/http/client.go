/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package http

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptrace"
	"net/url"
	"time"
	logger "wscan/core/utils/log"
)

type BytesCloser struct {
	*bytes.Reader
}

type PKCS12Config struct {
	Path     string
	Password string
}

type Client struct {
	*http.Client
	options    ClientOptions
	statistics *Statistics
}

func (*Client) AddFlowCallback(func(*Flow)) {

}

func (c *Client) BuildRequest(req *Request) (*http.Request, error) {
	// 应用 Headers 字段中的自定义 headers（由 WroteBack 从 DefaultHeaders 转换而来）
	for key, values := range c.options.Headers {
		if _, ok := req.Header[key]; !ok {
			for _, value := range values {
				req.Header.Add(key, value)
			}
		}
	}
	// 兼容：如果 WroteBack 未被调用，仍然从 DefaultHeaders 中读取 headers
	for key, value := range c.options.DefaultHeaders {
		if _, ok := req.Header[key]; !ok {
			req.Header.Set(key, value)
		}
	}

	bodyReader := bytes.NewReader(req.body)
	if req.Method == "" {
		req.Method = "GET"
	}
	rawReq, err := http.NewRequest(req.Method, req.url.String(), bodyReader)
	rawReq.Header = cloneHeader(req.Header)

	if err != nil {
		return nil, err
	}
	return rawReq, nil
}

func (*Client) CloneWithNewJar() *Client {
	return nil
}

func (*Client) CloneWithNewOptions(options *ClientOptions, new bool) *Client {
	return &Client{options: *options}
}

func (*Client) CloneWithoutJar() *Client {
	return nil
}

func (c *Client) DoRaw(req *Request) (*Response, error) {
	resp := &Response{
		Timing: &Timing{},
	}
	trace := &httptrace.ClientTrace{}
	r, err := c.BuildRequest(req)
	if err != nil {
		logger.Warnf("build request error: %v", err)
		return nil, err
	}
	reqRaw := req.Dump()
	before := time.Now()
	resp.NativeResponse, err = c.Client.Do(r)
	after := time.Now()
	if err != nil {
		c.statistics.respondFailed()
		logger.Warnf("%s\n%s %s \n%s", err.Error(), r.Method, r.URL.String(), reqRaw)
		return nil, err
	}
	c.statistics.respondSucceeded()

	req.TimeStamp = before.UnixMilli()
	resp.TimeStamp = after.UnixMilli()
	r = r.WithContext(httptrace.WithClientTrace(r.Context(), trace))
	c.statistics.AddResponseTime(resp.TimeStamp - req.TimeStamp)
	c.statistics.requestSent()

	if len(req.body) == 0 {
		logger.Debugf("%s %s %d ms\n%s", r.Method, r.URL.String(), resp.TimeStamp-req.TimeStamp, string(reqRaw))
	} else {
		logger.Debugf("%s %s %d ms\n%s", r.Method, r.URL.String(), resp.TimeStamp-req.TimeStamp, string(reqRaw))
	}

	resp.Status = resp.NativeResponse.Status
	resp.StatusCode = resp.NativeResponse.StatusCode
	resp.Header = resp.NativeResponse.Header
	resp.url = resp.NativeResponse.Request.URL
	resp.rawBody, _ = io.ReadAll(resp.NativeResponse.Body)
	resp.NativeResponse.Body = io.NopCloser(bytes.NewReader(resp.rawBody))
	resp.Text = string(resp.rawBody)
	UpdateResponseFromRawResponse(resp.NativeResponse, resp)
	return resp, nil
}

func (*Client) NativeClient() *Client {
	return nil
}

func (c *Client) Options() *ClientOptions {
	return &c.options
}

func (c *Client) Respond(ctx context.Context, req *Request) (*Response, error) {
	return c.doWithRetries(req, 1)
}

func (*Client) RespondWithoutBody(context.Context, *Request) (*Response, error) {

	return nil, nil
}

func (c *Client) Stater() *Statistics {
	return c.statistics
}

func (c *Client) WithStatistics(statistics *Statistics) *Client {
	c.statistics = statistics
	return c
}

// 多次尝试
func (c *Client) doWithRetries(req *Request, retry int) (*Response, error) {
	var err error
	var response *Response
	for i := 0; i <= retry; i++ {
		if response, err = c.DoRaw(req); err == nil {
			return response, nil
		}
	}
	return nil, err
}

func (c *Client) respond() {

}

func NewTransport(options *ClientOptions) *http.Transport {
	tlsConfig := &tls.Config{InsecureSkipVerify: false}

	// 加载 PKCS12 客户端证书
	if options.PKCS12.Path != "" {
		cert, _, err := ParsePKCS12FromFile(options.PKCS12.Path, options.PKCS12.Password)
		if err != nil {
			logger.Debugf("pkcs12: failed to load client certificate from %s: %v", options.PKCS12.Path, err)
		} else {
			tlsConfig.Certificates = append(tlsConfig.Certificates, cert)
		}
	}

	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}
	if options.Proxy != "" {
		proxyUrl, err := url.Parse(options.Proxy)
		if err == nil {
			transport.Proxy = http.ProxyURL(proxyUrl)
		}
	}
	return transport
}

func (c *Client) init() {
	clientCookieJar, _ := cookiejar.New(nil)
	c.Client = &http.Client{
		Timeout:   10 * time.Second,
		Transport: NewTransport(&c.options),
		Jar:       clientCookieJar,
	}
	// 设置是否跟踪跳转
	c.Client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}

}

func NewClient() *Client {
	c := &Client{
		statistics: &Statistics{responseTimeHistory: make(map[int64]*responseTime)},
	}
	c.init()
	return c
}

func NewClientWithOptions(opt *ClientOptions) *Client {
	clientCookieJar, _ := cookiejar.New(nil)

	tlsConfig := &tls.Config{
		InsecureSkipVerify: opt.TLSSkipVerify,
		MinVersion:         opt.TLSMinVersion,
		MaxVersion:         opt.TLSMaxVersion,
	}

	// 加载 PKCS12 客户端证书
	if opt.PKCS12.Path != "" {
		cert, _, err := ParsePKCS12FromFile(opt.PKCS12.Path, opt.PKCS12.Password)
		if err != nil {
			logger.Debugf("pkcs12: failed to load client certificate from %s: %v", opt.PKCS12.Path, err)
		} else {
			tlsConfig.Certificates = append(tlsConfig.Certificates, cert)
		}
	}

	transport := &http.Transport{
		DialContext:           (&net.Dialer{Timeout: time.Duration(opt.DialTimeout) * time.Second}).DialContext,
		TLSHandshakeTimeout:   time.Duration(opt.TLSHandshakeTimeout) * time.Second,
		ResponseHeaderTimeout: time.Duration(opt.ReadTimeout) * time.Second,
		IdleConnTimeout:       time.Duration(opt.IdleConnTimeout) * time.Second,
		MaxConnsPerHost:       opt.MaxConnsPerHost,
		MaxIdleConns:          opt.MaxIdleConns,
		TLSClientConfig:       tlsConfig,
	}
	if opt.Proxy != "" {
		proxyUrl, _ := url.Parse(opt.Proxy)
		transport.Proxy = http.ProxyURL(proxyUrl)
	}
	c := &Client{options: *opt,
		statistics: &Statistics{responseTimeHistory: make(map[int64]*responseTime)}}
	c.Client = &http.Client{
		Timeout:   10 * time.Second,
		Transport: transport,
		Jar:       clientCookieJar,
	}
	c.Client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return c
}
