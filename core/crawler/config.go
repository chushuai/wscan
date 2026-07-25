/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package crawler

import (
	"fmt"
	"time"
	"wscan/core/http"
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

type Config struct {
	Proxy             string                        `yaml:"-"`
	HTTPClientOptions *http.ClientOptions           `yaml:"-"`
	EnableImage       bool                          `yaml:"enable-image-display" #:"启用图片显示，适用于需要验证码登录的情况，启用wait-login自动开启"`
	Browser           bool                          `yaml:"-"`
	LoadWait          int                           `yaml:"load-wait" #:"页面加载完毕后的等待时间，单位秒，网速不佳时可尝试调大该值"`
	ExecPath          string                        `yaml:"exec-path" #:"启动chrome的路径"`
	DisableHeadless   bool                          `yaml:"disable-headless" #:"禁用无头模式"`
	ForceSandbox      bool                          `yaml:"force-sandbox" #:"强制开启sandbox"`
	Restrictions      *checker.RequestCheckerConfig `yaml:"gogo"`
	// 以下字段原属 RestrictionsOnRequests，直接放在 Config 避免来回拷贝遗漏
	MaxConcurrent  int `yaml:"max-concurrent" #:"最大页面并发（不大于10）"`
	MaxDepth       int `yaml:"max-depth" #:"最大页面深度限制，0为无限制"`
	MaxCountOfURLs int `yaml:"max-count-of-page" #:"最多爬取的页面数量限制，0为无限制"`
	//ClientConfig           `yaml:"-"`
	AuthConfig  `yaml:"-" #:"认证配置"`
	Distributed `yaml:"-"`
	TaskConfig  *TaskConfig
	// Browser-specific fields
	WindowWidth              int    `yaml:"window-width" #:"浏览器窗口宽度"`
	WindowHeight             int    `yaml:"window-height" #:"浏览器窗口高度"`
	NavigateTimeoutSecond    int    `yaml:"navigate-timeout-second" #:"访问超时时间，单位秒"`
	LoadTimeoutSecond        int    `yaml:"load-timeout-second" #:"加载超时时间，单位秒"`
	Retry                    int    `yaml:"retry" #:"页面访问失败后的重试次数"`
	PageAnalyzeTimeoutSecond int    `yaml:"page-analyze-timeout-second" #:"页面分析超时时间，单位秒"`
	MaxInteractive           int    `yaml:"max-interactive" #:"单个页面最大交互次数"`
	MaxInteractiveDepth      int    `yaml:"max-interactive-depth" #:"页面交互深度限制"`
	MaxPageVisitPerSite      int    `yaml:"max-page-visit-per-site" #:"每个站点最多访问的页面数量"`
	ElementFilterStrength    int    `yaml:"element-filter-strength" #:"过滤同站点相似元素强度"`
	ParentPathDetect         bool   `yaml:"parent-path-detect" #:"是否启用父目录探测功能"`
	TabInitJS                string `yaml:"tab-init-js" #:"每个标签页初始化时执行的JS代码"`
	// Basic-crawler specific
	AllowVisitParentPath bool `yaml:"allow-visit-parent-path" #:"是否允许爬取父目录"`
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

type NodeEvents struct {
	Selector string
	Events   []string
}

type part struct {
	IsFile    bool
	FieldName string
	FileName  string
	Value     []string
}

func (c *Config) Correct() (*Config, error) {
	if c == nil {
		return nil, fmt.Errorf("crawler config is nil")
	}
	// Correct concurrency
	if c.MaxConcurrent <= 0 {
		c.MaxConcurrent = 10
	}
	if c.MaxConcurrent > 10 {
		c.MaxConcurrent = 10
	}
	// Correct crawl depth
	if c.MaxDepth < 0 {
		c.MaxDepth = 0 // 0 means unlimited
	}
	// Correct page count limit
	if c.MaxCountOfURLs < 0 {
		c.MaxCountOfURLs = 0
	}
	if c.MaxCountOfURLs == 0 {
		c.MaxCountOfURLs = MaxCrawlCount
	}
	// Correct load wait time
	if c.LoadWait <= 0 {
		c.LoadWait = 5
	}
	// Validate auth config
	if c.AuthConfig.BasicAuth != nil {
		if c.AuthConfig.BasicAuth.Username == "" || c.AuthConfig.BasicAuth.Password == "" {
			return nil, fmt.Errorf("basic auth requires both username and password")
		}
	}
	if c.AuthConfig.FormAuth != nil {
		if c.AuthConfig.FormAuth.URL == "" {
			return nil, fmt.Errorf("form auth requires a URL")
		}
	}
	return c, nil
}

var StaticSuffix = []string{
	"png", "gif", "jpg", "mp4", "mp3", "mng", "pct", "bmp", "jpeg", "pst", "psp", "ttf",
	"tif", "tiff", "ai", "drw", "wma", "ogg", "wav", "ra", "aac", "mid", "au", "aiff",
	"dxf", "eps", "ps", "svg", "3gp", "asf", "asx", "avi", "mov", "mpg", "qt", "rm",
	"wmv", "m4a", "bin", "xls", "xlsx", "ppt", "pptx", "doc", "docx", "odt", "ods", "odg",
	"odp", "exe", "zip", "rar", "tar", "gz", "iso", "rss", "pdf", "txt", "dll", "ico",
	"gz2", "apk", "crt", "woff", "woff2", "webp", "less", "dmg", "bz2", "otf", "swf",
	"flv", "mpeg", "dat", "xsl", "csv", "cab", "exif", "wps", "m4v", "rmvb",
}

// 请求的来源
const (
	FromTarget      = "Target"     //初始输入的目标
	FromNavigation  = "Navigation" //页面导航请求
	FromXHR         = "XHR"        //ajax异步请求
	FromDOM         = "DOM"        //dom解析出来的请求
	FromJSFile      = "JavaScript" //JS脚本中解析
	FromFuzz        = "PathFuzz"   //初始path fuzz
	FromRobots      = "robots.txt" //robots.txt
	FromComment     = "Comment"    //页面中的注释
	FromWebSocket   = "WebSocket"
	FromEventSource = "EventSource"
	FromFetch       = "Fetch"
	FromHistoryAPI  = "HistoryAPI"
	FromOpenWindow  = "OpenWindow"
	FromHashChange  = "HashChange"
	FromStaticRes   = "StaticResource"
	FromStaticRegex = "StaticRegex"
)

// 请求方法
const (
	GET     = "GET"
	POST    = "POST"
	PUT     = "PUT"
	DELETE  = "DELETE"
	HEAD    = "HEAD"
	OPTIONS = "OPTIONS"
)

// 过滤模式
const (
	SimpleFilterMode = "simple"
	SmartFilterMode  = "smart"
	StrictFilterMode = "strict"
)

// 事件触发模式
const (
	EventTriggerAsync = "async"
	EventTriggerSync  = "sync"
)

var ScriptSuffix = []string{
	"php", "asp", "jsp", "asa",
}

const (
	DefaultUA               = "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.0 Safari/537.36"
	MaxTabsCount            = 10
	TabRunTimeout           = 20 * time.Second
	DefaultInputText        = "Crawler"
	FormInputKeyword        = "Crawler"
	SuspectURLRegex         = `(?:"|')(((?:[a-zA-Z]{1,10}://|//)[^"'/]{1,}\.[a-zA-Z]{2,}[^"']{0,})|((?:/|\.\./|\./)[^"'><,;|*()(%%$^/\\\[\]][^"'><,;|()]{1,})|([a-zA-Z0-9_\-/]{1,}/[a-zA-Z0-9_\-/]{1,}\.(?:[a-zA-Z]{1,4}|action)(?:[\?|#][^"|']{0,}|))|([a-zA-Z0-9_\-/]{1,}/[a-zA-Z0-9_\-/]{3,}(?:[\?|#][^"|']{0,}|))|([a-zA-Z0-9_\-]{1,}\.(?:php|asp|aspx|jsp|json|action|html|js|txt|xml)(?:[\?|#][^"|']{0,}|)))(?:"|')`
	URLRegex                = `((https?|ftp|file):)?//[-A-Za-z0-9+&@#/%?=~_|!:,.;]+[-A-Za-z0-9+&@#/%=~_|]`
	AttrURLRegex            = ``
	DomContentLoadedTimeout = 5 * time.Second
	EventTriggerInterval    = 100 * time.Millisecond // 单位毫秒
	BeforeExitDelay         = 1 * time.Second
	DefaultEventTriggerMode = EventTriggerAsync
	MaxCrawlCount           = 200
)

var DefaultIgnoreKeywords = []string{"logout", "quit", "exit"}
var AllowedFormName = []string{"default", "mail", "code", "phone", "username", "password", "qq", "id_card", "url", "date", "number"}

type ContinueResourceList []string

var InputTextMap = map[string]map[string]any{
	"mail": {
		"keyword": []string{"mail"},
		"value":   "scan@gmail.com",
	},
	"code": {
		"keyword": []string{"yanzhengma", "code", "ver", "captcha"},
		"value":   "123a",
	},
	"phone": {
		"keyword": []string{"phone", "number", "tel", "shouji"},
		"value":   "18812345678",
	},
	"username": {
		"keyword": []string{"name", "user", "id", "login", "account"},
		"value":   "scan@gmail.com",
	},
	"password": {
		"keyword": []string{"pass", "pwd"},
		"value":   "scanner#$3435.",
	},
	"qq": {
		"keyword": []string{"qq", "wechat", "tencent", "weixin"},
		"value":   "123456789",
	},
	"IDCard": {
		"keyword": []string{"card", "shenfen"},
		"value":   "511702197409284963",
	},
	"url": {
		"keyword": []string{"url", "site", "web", "blog", "link"},
		"value":   "https://scan.nice.cn/",
	},
	"date": {
		"keyword": []string{"date", "time", "year", "now"},
		"value":   "2000-01-01",
	},
	"number": {
		"keyword": []string{"day", "age", "num", "count"},
		"value":   "10",
	},
}
