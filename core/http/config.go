/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package http

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"strings"

	"golang.org/x/crypto/pkcs12"
)

type Server struct {
	Addr   string `json:"addr" yaml:"addr"`
	Weight int    `json:"weight" yaml:"weight"`
}

type StatRepr struct {
	FoundNumber             int64
	ScannedNumber           int64
	RequestNumber           int64
	RatioFailedHTTPRequests float32
	AverageResponseTime     float32
}
type Rule struct {
	Match   string   `json:"match" yaml:"match"`
	Servers []Server `json:"servers" yaml:"servers"`
}

type ClientOptions struct {
	Proxy               string              `json:"proxy" yaml:"proxy" #:"漏洞扫描时使用的代理，如: http://127.0.0.1:8080。 如需设置多个代理，请使用 proxy_rule 或自行创建上层代理"`
	ProxyRule           []Rule              `json:"proxy_rule" yaml:"proxy_rule" #:"漏洞扫描使用多个代理的配置规则, 具体请参照文档"`
	DialTimeout         int                 `json:"dial_timeout" yaml:"dial_timeout" #:"建立 tcp 连接的超时时间"`
	ReadTimeout         int                 `json:"read_timeout" yaml:"read_timeout" #:"读取 http 响应的超时时间，不可太小，否则会影响到 sql 时间盲注的判断"`
	MaxConnsPerHost     int                 `json:"max_conns_per_host" yaml:"max_conns_per_host" #:"同一 host 最大允许的连接数，可以根据目标主机性能适当增大"`
	EnableHTTP2         bool                `json:"enable_http2" yaml:"enable_http2" #:"是否启用 http2, 开启可以提升部分网站的速度，但目前不稳定有崩溃的风险"`
	PKCS12              PKCS12Config        `json:"pkcs12" yaml:"pkcs12"`
	TLSSkipVerify       bool                `json:"-" yaml:"-"`
	TLSHandshakeTimeout int                 `json:"-" yaml:"-"`
	IdleConnTimeout     int                 `json:"-" yaml:"-"`
	MaxIdleConns        int                 `json:"-" yaml:"-"`
	TLSMinVersion       uint16              `json:"-" yaml:"-"`
	TLSMaxVersion       uint16              `json:"-" yaml:"-"`
	FailRetries         int                 `json:"fail_retries" yaml:"fail_retries" #:"请求失败的重试次数，0 则不重试"`
	MaxRedirect         int                 `json:"max_redirect" yaml:"max_redirect" #:"单个请求最大允许的跳转数"`
	MaxRespBodySize     int64               `json:"max_resp_body_size" yaml:"max_resp_body_size" #:"最大允许的响应大小, 默认 2M"`
	MaxQPS              float64             `json:"max_qps" yaml:"max_qps" #:"每秒最大请求数"`
	AllowMethods        []string            `json:"allow_methods" yaml:"allow_methods" #:"允许的请求方法"`
	Headers             map[string][]string `json:"-" yaml:"-"`
	Cookies             map[string]string   `json:"cookies" yaml:"-"`
	DefaultHeaders      map[string]string   `json:"headers" yaml:"headers"`
}

func (*ClientOptions) SetProxies([]string) {

}
func (o *ClientOptions) WroteBack() {
	if o.DefaultHeaders == nil {
		return
	}
	if o.Headers == nil {
		o.Headers = make(map[string][]string)
	}
	if o.Cookies == nil {
		o.Cookies = make(map[string]string)
	}
	for k, v := range o.DefaultHeaders {
		// Cookie 单独存储到 Cookies 字段
		if k == "Cookie" {
			// 解析 Cookie: key1=value1; key2=value2
			parts := strings.Split(v, ";")
			for _, part := range parts {
				part = strings.TrimSpace(part)
				if idx := strings.Index(part, "="); idx > 0 {
					o.Cookies[part[:idx]] = part[idx+1:]
				}
			}
		}
		o.Headers[k] = append(o.Headers[k], v)
	}
}

func ParsePKCS12FromFile(path string, password string) (tls.Certificate, []*x509.Certificate, error) {
	if path == "" {
		return tls.Certificate{}, nil, fmt.Errorf("pkcs12: file path is empty")
	}

	p12Data, err := os.ReadFile(path)
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("pkcs12: failed to read file %s: %w", path, err)
	}

	return ParsePKCS12(p12Data, password)
}

// ParsePKCS12 解析 PKCS12 (.p12/.pfx) 格式的证书数据，
// 返回可用于 tls.Config 的证书和 CA 证书链
func ParsePKCS12(p12Data []byte, password string) (tls.Certificate, []*x509.Certificate, error) {
	privateKey, cert, err := pkcs12.Decode(p12Data, password)
	if err != nil {
		return tls.Certificate{}, nil, fmt.Errorf("pkcs12: failed to decode: %w", err)
	}

	tlsCert := tls.Certificate{
		Certificate: [][]byte{cert.Raw},
		PrivateKey:  privateKey,
		Leaf:        cert,
	}

	return tlsCert, nil, nil
}

const (
	JSONContentType = "application/json"
	URLEncoded      = "application/x-www-form-urlencoded"
	Multipart       = "multipart/form-data"
)
