/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package http

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
	HEADER_NO_USE       map[string]string   `json:"headers" yaml:"headers"`
}

func (*ClientOptions) SetProxies([]string) {

}
func (*ClientOptions) WroteBack() {

}

func ParsePKCS12FromFile() {

}
