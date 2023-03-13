/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package http

import (
	"bytes"
	"context"
	"net/http"
	"net/http/cookiejar"
	"time"
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
	options ClientOptions
}

func (*Client) AddFlowCallback(func(*Flow)) {

}

func (*Client) BuildRequest(*Request) (*http.Request, error) {
	return nil, nil
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
	r, err := c.BuildRequest(req)
	if err != nil {
		return nil, err
	}
	// 请求
	var resp *http.Response
	resp, err = c.Client.Do(r)
	if err != nil {
		return nil, err
	}
	return NewResponse(resp), nil
}

func (*Client) NativeClient() *Client {
	return nil
}

func (c *Client) Options() *ClientOptions {
	return &c.options
}

func (*Client) Respond(context.Context, *Request) (*Response, error) {
	return nil, nil
}

func (*Client) RespondWithoutBody(context.Context, *Request) (*Response, error) {

	return nil, nil
}

func (*Client) Stater() *Statistics {
	return nil
}

func (*Client) WithStatistics(*Statistics) *Client {
	return nil
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

func (c *Client) init() {

	// 设置是否跟踪跳转
	//if !c.options.re {
	//	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
	//		return http.ErrUseLastResponse
	//	}
	//}
	clientCookieJar, _ := cookiejar.New(nil)

	c.Client = &http.Client{
		Timeout:   10 * time.Second,
		Transport: NewTransport(&c.options),
		Jar:       clientCookieJar,
	}
}

func (c *Client) respond() {

}

func NewClient() *Client {
	return &Client{}
}

func NewClientWithOptions(opt *ClientOptions) *Client {
	return &Client{options: *opt}
}
