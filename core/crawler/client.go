/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package crawler

import (
	"crypto/tls"
	"golang.org/x/crypto/pkcs12"
	"golang.org/x/net/context"
	"golang.org/x/time/rate"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"sync"
	"time"
)

type ClientConfig struct {
	Proxies             []string
	DialTimeout         int
	TLSHandshakeTimeout int
	ReadTimeout         int
	IdleConnTimeout     int
	MaxConnsPerHost     int
	MaxIdleConns        int
	TLSSkipVerify       bool
	TLSMinVersion       uint16
	TLSMaxVersion       uint16
	PKCS12Certificate   []byte
	PKCS12Password      string
	MaxRetryTimes       int
	MaxRedirectTimes    int
	MaxRequestPerSecond int
	MaxRespBodySize     int64
	AllowedMethods      []string
}

type ClientStatistic struct {
	SentRequestsCount               int32
	FailedRequestsCount             int32
	ResponsesCount                  int32
	TotalResponseTime               int64
	AverageResponseTime             int64
	TotalResponseTimeInTenSeconds   int64
	AverageResponseTimeInTenSeconds int64
}

type Client struct {
	ctx                   context.Context
	Jar                   *cookiejar.Jar
	Client                *http.Client
	ClientWithoutRedirect *http.Client
	config                *ClientConfig
	limiter               *rate.Limiter
	requestTimeout        int64
	ClientStatistic
	respCountInTenSecond int32
	lastTenSecondTime    time.Time
	statisticMutex       sync.Mutex
}

func NewRoundRobinProxyFunc(proxies []string) func(*http.Request) (*url.URL, error) {
	var idx int32
	return func(req *http.Request) (*url.URL, error) {
		if len(proxies) == 0 {
			return nil, nil
		}
		url, err := url.Parse(proxies[idx])
		if err != nil {
			return nil, err
		}
		idx = (idx + 1) % int32(len(proxies))
		return url, nil
	}
}

func NewClient(config *ClientConfig) (*Client, error) {
	// 创建一个新的 CookieJar
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}

	// 创建一个 Transport
	transport := &http.Transport{
		DialContext:           (&net.Dialer{Timeout: time.Duration(config.DialTimeout) * time.Second}).DialContext,
		TLSHandshakeTimeout:   time.Duration(config.TLSHandshakeTimeout) * time.Second,
		ResponseHeaderTimeout: time.Duration(config.ReadTimeout) * time.Second,
		IdleConnTimeout:       time.Duration(config.IdleConnTimeout) * time.Second,
		MaxConnsPerHost:       config.MaxConnsPerHost,
		MaxIdleConns:          config.MaxIdleConns,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: config.TLSSkipVerify,
			MinVersion:         config.TLSMinVersion,
			MaxVersion:         config.TLSMaxVersion,
		},
	}
	if len(config.Proxies) > 0 {
		transport.Proxy = NewRoundRobinProxyFunc(config.Proxies)
	}

	if len(config.PKCS12Certificate) > 0 {
		privateKey, cert, err := pkcs12.Decode(config.PKCS12Certificate, config.PKCS12Password)
		if err != nil {
			return nil, err
		}
		tlsCert := tls.Certificate{
			Certificate: [][]byte{cert.Raw},
			PrivateKey:  privateKey,
			Leaf:        cert,
		}
		transport.TLSClientConfig.Certificates = []tls.Certificate{tlsCert}
	}

	// 创建一个带 CookieJar 和 Transport 的 Client
	client := &http.Client{
		Jar:       jar,
		Transport: transport,
	}

	// 创建一个不跟随重定向的 Client
	clientWithoutRedirect := &http.Client{
		Jar:       jar,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// 创建一个速率限制器
	limiter := rate.NewLimiter(rate.Limit(config.MaxRequestPerSecond), config.MaxRequestPerSecond)

	// 创建一个新的 Client 实例
	// 创建 Client 实例
	return &Client{
		ctx:                   context.Background(),
		Jar:                   jar,
		Client:                client,
		ClientWithoutRedirect: clientWithoutRedirect,
		config:                config,
		limiter:               limiter,
		requestTimeout:        int64(config.ReadTimeout + config.TLSHandshakeTimeout),
	}, nil
}

func (c *Client) Do(req *http.Request) (*http.Response, error) {
	return c.do(req, true)
}

func (c *Client) DoWithRetry(req *http.Request, redirect bool) (*http.Response, error) {
	var resp *http.Response
	var err error

	for i := 0; i < c.config.MaxRetryTimes; i++ {
		resp, err = c.do(req, redirect)

		if err == nil && resp.StatusCode < 400 {
			break
		}

		time.Sleep(time.Duration(i+1) * time.Second)
	}

	return resp, err
}

func (c *Client) DoWithoutRedirect(req *http.Request) (*http.Response, error) {

	return c.do(req, false)
}

func (c *Client) GetStatistic() *ClientStatistic {
	c.statisticMutex.Lock()
	defer c.statisticMutex.Unlock()

	// Calculate the current average response time
	c.calculateAverageResponseTime(time.Now())

	// Return a copy of the current statistics
	return &ClientStatistic{
		SentRequestsCount:               c.SentRequestsCount,
		FailedRequestsCount:             c.FailedRequestsCount,
		ResponsesCount:                  c.ResponsesCount,
		TotalResponseTime:               c.TotalResponseTime,
		AverageResponseTime:             c.AverageResponseTime,
		TotalResponseTimeInTenSeconds:   c.TotalResponseTimeInTenSeconds,
		AverageResponseTimeInTenSeconds: c.AverageResponseTimeInTenSeconds,
	}
}

// func (*Client) calculateAverageResponseTime(time.Time)
func (c *Client) calculateAverageResponseTime(now time.Time) {
	c.statisticMutex.Lock()
	defer c.statisticMutex.Unlock()

	if now.Sub(c.lastTenSecondTime) > 10*time.Second {
		c.AverageResponseTimeInTenSeconds = c.TotalResponseTimeInTenSeconds / int64(c.respCountInTenSecond)
		c.TotalResponseTimeInTenSeconds = 0
		c.respCountInTenSecond = 0
		c.lastTenSecondTime = now
	}

	c.AverageResponseTime = c.TotalResponseTime / int64(c.ResponsesCount)
}

// func (*Client) do(*http.Request, bool) (*http.Response, error)
func (c *Client) do(req *http.Request, redirect bool) (*http.Response, error) {
	// Create a copy of the request and set its headers
	copiedReq := req.Clone(req.Context())
	c.makeHeadersCopier()(copiedReq.Header)

	// Set the request's cookies
	c.Jar.SetCookies(req.URL, copiedReq.Cookies())

	// Create a new HTTP client for this request
	httpClient := c.Client
	if !redirect {
		httpClient = c.ClientWithoutRedirect
	}

	// 首先获取令牌以等待请求速率符合限制
	//err := c.limiter.Wait(c.ctx)
	//if err != nil {
	//	return nil, fmt.Errorf("failed to wait for rate limiter: %v", err)
	//}

	// Send the request and record statistics
	resp, err := httpClient.Do(copiedReq)
	if err != nil {
		c.FailedRequestsCount++
	} else {
		c.ResponsesCount++
		//c.TotalResponseTime += 0
		//c.TotalResponseTimeInTenSeconds += 0
		c.respCountInTenSecond++
	}

	// Update the request's cookies
	// c.Jar.SetCookies(req.URL, resp.Cookies())

	return resp, err
}

//func (*Client) makeHeadersCopier()
func (c *Client) makeHeadersCopier() func(http.Header) {
	return func(dst http.Header) {

	}
}
