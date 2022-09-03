/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package crawler

import (
	"regexp"
	"sync"
	"wscan/core/utils/checker"
)

type AuthConfig struct {
	BasicAuth *BasicAuth `yaml:"basic-auth" #:"http基础(basic)认证"`
	FormAuth  *FormAuth  `yaml:"-" #:"表单认证，仅支持识别只需要输入用户名和密码的登录页面"`
}

type BasicAuth struct {
	Username string `yaml:"username" #:"用户名"`
	Password string `yaml:"password" #:"密码"`
}

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
	PKCS12Certificate   []uint8
	PKCS12Password      string
	MaxRetryTimes       int
	MaxRedirectTimes    int
	MaxRequestPerSecond int
	MaxRespBodySize     int64
	AllowedMethods      []string
}

type RestrictionsOnURLs struct {
	DisallowedSuffix                 []string `yaml:"disallowed-suffix" #:"不允许的文件后缀"`
	disallowedSuffix                 sync.Map
	DisallowedKeywordsInPathAndQuery []string `yaml:"disallowed-keywords-in-path-and-query" #:"不允许的URL关键字"`
	DisallowedDomains                []string `yaml:"disallowed-domain" #:"不允许的域名"`
	DisallowedURLs                   []string `yaml:"disallowed-urls" #:"不允许的URL（正则）"`
	disallowedURLs                   []*regexp.Regexp
	AllowedDomains                   []string `yaml:"allowed-domains" #:"允许的域名，起始目标会被自动加入其中"`
	AllowedURLs                      []string `yaml:"allowed-urls" #:"允许的URL（正则）"`
	allowedURLs                      []*regexp.Regexp
	AllowVisitParentPath             bool `yaml:"-"`
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

type Config struct {
	XrayProxy              string                        `yaml:"-"`
	EnableImage            bool                          `yaml:"enable-image-display" #:"启用图片显示，适用于需要验证码登录的情况，启用wait-login自动开启"`
	Browser                bool                          `yaml:"-"`
	LoadWait               int                           `yaml:"load-wait" #:"页面加载完毕后的等待时间，单位秒，网速不佳时可尝试调大该值"`
	ExecPath               string                        `yaml:"exec-path" #:"启动chrome的路径"`
	DisableHeadless        bool                          `yaml:"disable-headless" #:"禁用无头模式"`
	Restrictions           *checker.RequestCheckerConfig `yaml:"gogo"`
	RequestConfig          `yaml:"request-config" #:"请求头配置"`
	ClientConfig           `yaml:"-"`
	AuthConfig             `yaml:"-" #:"认证配置"`
	RestrictionsOnURLs     `yaml:"restrictions-on-urls" #:"对爬取的URL的一些限制项"`
	RestrictionsOnRequests `yaml:"restrictions-on-requests" #:"对请求行为的一些限制项"`
	Distributed            `yaml:"-"`
}

type Cookie struct {
	Name                 string `yaml:"name" #:"cookie的name"`
	Value                string `yaml:"value" #:"cookie的value"`
	AllowCookiesOverride bool   `yaml:"-"`
}

type CrawlerStatistic struct {
	CreatedRequestsCount   int32
	RequestedRequestsCount int32
	WorkingTasksCount      int32
	WorkerCount            int32
}

type Distributed struct {
	RedisURL        string
	RedisKey        string
	RedisKeyTimeout int
}

type FormAuth struct {
	URL      string `yaml:"url" #:"表单认证页的URL"`
	Username string `yaml:"username" #:"用户名"`
	Password string `yaml:"password" #:"密码"`
}

type Header struct {
	Key   string `yaml:"key" #:"header的key"`
	Value string `yaml:"value" #:"header的value"`
}

type NodeEvents struct {
	Selector string
	Events   []string
}

type RequestConfig struct {
	UserAgent string   `yaml:"user-agent" #:"请求user-agent配置"`
	Headers   []Header `yaml:"headers" #:"请求header配置"`
	Cookies   []Cookie `yaml:"cookies" #:"请求cookie配置"`
}

type RestrictionsOnRequests struct {
	MaxConcurrent          int   `yaml:"max-concurrent" #:"最大页面并发（不大于10）"`
	MaxDepth               int   `yaml:"max-depth" #:"最大页面深度限制"`
	MaxClickDepth          int   `yaml:"max-click-depth" #:"一个页面中最大点击深度限制"`
	MaxCountOfURLs         int   `yaml:"max-count-of-page" #:"最多爬取的页面数量限制"`
	MaxClickOrEventTrigger int32 `yaml:"max-click-or-event-trigger" #:"单个页面中最大点击或事件触发次数(不大于10000)"`
	ClickOrEventInterval   int   `yaml:"click-or-event-interval" #:"点击间隔，单位毫秒"`
}

type part struct {
	IsFile    bool
	FieldName string
	FileName  string
	Value     []string
}
