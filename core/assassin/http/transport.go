/**
2 * @Author: shaochuyu
3 * @Date: 9/8/22
4 */

package http

import (
	"crypto/tls"
	"net/http"
	"net/url"
)

type Transport struct {
	*http.Transport
}

func NewTransport(options *ClientOptions) *Transport {
	tr := Transport{}
	tr.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: false},
	}
	if options.Proxy != "" {
		proxyUrl, err := url.Parse(options.Proxy)
		if err == nil {
			tr.Proxy = http.ProxyURL(proxyUrl)
		}
	}
	return &tr
}
