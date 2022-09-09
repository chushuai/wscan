/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package http

import (
	"bytes"
	"context"
	"net/http"
)

type BytesCloser struct {
	*bytes.Reader
}

//type Client struct {
//	Transport     http.RoundTripper
//	CheckRedirect func(*http.Request, []*http.Request) error
//	Jar           http.CookieJar
//	Timeout       int64
//}

type PKCS12Config struct {
	Path     string
	Password string
}

//type Client struct {
//	c              *Client
//	frankC         *Client
//	qps            *rate.Limiter
//	options        ClientOptions
//	statistics     *Statistics
//	flowDispatcher *flowDispatcher
//}

type Client struct {
	*http.Client
}

func (*Client) AddFlowCallback(func(*Flow)) {

}
func (*Client) BuildRequest(*Request) (*Request, error) {
	return nil, nil
}
func (*Client) CloneWithNewJar() *Client {
	return nil
}
func (*Client) CloneWithNewOptions(*ClientOptions, bool) *Client {
	return nil
}
func (*Client) CloneWithoutJar() *Client {
	return nil
}
func (*Client) DoRaw(*Request, bool) (*Response, error) {
	return nil, nil
}
func (*Client) NativeClient() *Client {
	return nil
}
func (*Client) Options() *ClientOptions {
	return nil
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
func (*Client) doWithRetries() {

}
func (*Client) init() {

}
func (*Client) respond() {

}
