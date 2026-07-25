/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package collector

import (
	"wscan/core/utils/checker"
)

type AuthCredential struct {
	Username string `yaml:"username" json:"username" #:"用户名"`
	Password string `yaml:"password" json:"password" #:"密码"`
}

// CrawlerCommonConfig 爬虫配置，包含通用配置、basic-crawler 和 browser-crawler 的配置
type CrawlerCommonConfig struct {
	BasicAuth     AuthCredential                `yaml:"basic_auth" json:"basic_auth" #:"目标网站的基础认证信息"`
	Restriction   *checker.RequestCheckerConfig `yaml:"restriction" json:"restriction" #:"爬虫的允许爬取的资源限制, 为空表示不限制。爬虫会自动添加扫描目标到 Hostname_allowed。"`
	BasicCrawler  BasicCrawlerConfig            `yaml:"basic-crawler" json:"basic-crawler"`
	BrowserConfig BrowserConfig                 `yaml:"browser-crawler" json:"browser-crawler"`
}

type BasicCrawlerConfig struct {
	MaxDepth             int  `yaml:"max_depth" json:"max_depth" #:"最大爬取深度， 0 为无限制"`
	MaxCountOfLinks      int  `yaml:"max_count_of_links" json:"max_count_of_links" #:"本次爬取收集的最大链接数, 0 为无限制"`
	AllowVisitParentPath bool `yaml:"allow_visit_parent_path" json:"allow_visit_parent_path" #:"是否允许爬取父目录, 如果扫描目标为 t.com/a/且该项为 false, 那么就不会爬取 t.com/ 这级的内容"`
}

type BrowserConfig struct {
	ExecPath                   string   `yaml:"exec_path" #:"启动chrome的路径"`
	DisableHeadless            bool     `yaml:"disable_headless" #:"禁用无头模式"`
	ForceSandbox               bool     `yaml:"force_sandbox" #:"强制开启sandbox；为 false 时默认开启沙箱，但在容器中会关闭沙箱。为true时强制启用沙箱，可能导致在docker中无法使用。"`
	EnableImage                bool     `yaml:"enable_image" #:"启用图片显示"`
	DisallowedResourceType     []string `yaml:"disallowedresourcetype" #:"禁止加载的资源类型列表"`
	Trace                      bool     `yaml:"trace" #:"启用chromedp trace日志"`
	ParentPathDetect           bool     `yaml:"parent_path_detect" #:"是否启用父目录探测功能"`
	Monitor                    string   `yaml:"monitor" #:"监控页面URL，用于调试"`
	MaxDepth                   int      `yaml:"max_depth" #:"最大页面深度限制"`
	Width                      int      `yaml:"width" #:"浏览器窗口宽度，0为默认1920"`
	Height                     int      `yaml:"height" #:"浏览器窗口高度，0为默认1080"`
	NavigateTimeoutSecond      int      `yaml:"navigate_timeout_second" #:"访问超时时间，单位秒"`
	LoadTimeoutSecond          int      `yaml:"load_timeout_second" #:"加载超时时间，单位秒"`
	Retry                      int      `yaml:"retry" #:"页面访问失败后的重试次数"`
	PageAnalyzeTimeoutSecond   int      `yaml:"page_analyze_timeout_second" #:"页面分析超时时间，单位秒"`
	MaxInteractive             int      `yaml:"max_interactive" #:"单个页面最大交互次数"`
	MaxInteractiveDepth        int      `yaml:"max_interactive_depth" #:"页面交互深度限制"`
	MaxPageConcurrent          int      `yaml:"max_page_concurrent" #:"最大页面并发（不大于10）"`
	MaxPageVisit               int      `yaml:"max_page_visit" #:"总共允许访问的页面数量"`
	MaxPageVisitPerSite        int      `yaml:"max_page_visit_per_site" #:"每个站点最多访问的页面数量"`
	MaxJSRedirect              int      `yaml:"maxjsredirect" #:"最大JS重定向次数，0为不限制"`
	DefaultURLs                []string `yaml:"defaulturls" #:"默认访问的URL列表"`
	TabInitJS                  string   `yaml:"tabinitjs" #:"每个标签页初始化时执行的JS代码"`
	ElementFilterStrength      uint8    `yaml:"element_filter_strength" #:"过滤同站点相似元素强度，1-7取值，强度逐步增大，为0时不进行跨页面元素过滤"`
	NewTaskDeduplicationOption uint8    `yaml:"newtaskdeduplicationoption" #:"新任务去重选项"`
	OutputDeduplicationOption  uint8    `yaml:"outputdeduplicationoption" #:"输出去重选项"`
	SendFormPost               bool     `yaml:"sendformpost" #:"是否发送表单POST请求"`
}

type MitmConfig struct {
	Listen          string                        `json:"-" yaml:"-"`
	CACert          string                        `json:"ca_cert" yaml:"ca_cert" #:"CA 根证书路径"`
	CAKey           string                        `json:"ca_key" yaml:"ca_key" #:"CA 私钥路径"`
	ProxyAuth       AuthCredential                `json:"basic_auth" yaml:"basic_auth" #:"基础认证的用户名密码"`
	AllowIPRange    []string                      `json:"allow_ip_range" yaml:"allow_ip_range" #:"允许的 ip，可以是 ip 或者 cidr 字符串"`
	Restriction     *checker.RequestCheckerConfig `json:"restriction" yaml:"restriction" #:"代理能够访问的资源限制, 以下各项为空表示不限制"`
	Queue           MitmQueueConfig               `json:"queue" yaml:"queue"`
	ProxyHeader     MitmProxyHeaderConfig         `json:"proxy_header" yaml:"proxy_header"`
	DownstreamProxy string                        `json:"upstream_proxy" yaml:"upstream_proxy" #:"为 mitm 本身配置独立的代理"`
	WebCtrlPage     string                        `json:"-" yaml:"-"`
	TTL             int64                         `json:"-" yaml:"-"`
}

type MitmProxyHeaderConfig struct {
	Via        string `json:"via" yaml:"via" #:"是否为代理自动添加 Via 头"`
	XForwarded bool   `json:"x_forwarded" yaml:"x_forwarded" #:"是否为代理自动添加 X-Forwarded-{For,Host,Proto,Url} 四个 http 头"`
}

type MitmQueueConfig struct {
	MaxLength int `json:"max_length" yaml:"max_length" #:"队列长度限制, 也可以理解为最大允许多少等待扫描的请求, 请根据内存大小自行调整"`
}
