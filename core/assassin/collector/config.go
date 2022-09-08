/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package collector

import "wscan/core/utils/checker"

type AuthCredential struct {
	Username string
	Password string
}

type BasicCrawlerConfig struct {
	MaxDepth             int                           `yaml:"max_depth" json:"max_depth" #:"最大爬取深度， 0 为无限制"`
	MaxCountOfLinks      int                           `yaml:"max_count_of_links" json:"max_count_of_links" #:"本次爬取收集的最大链接数, 0 为无限制"`
	AllowVisitParentPath bool                          `yaml:"allow_visit_parent_path" json:"allow_visit_parent_path" #:"是否允许爬取父目录, 如果扫描目标为 t.com/a/且该项为 false, 那么就不会爬取 t.com/ 这级的内容"`
	Restriction          *checker.RequestCheckerConfig `yaml:"restriction" json:"restriction" #:"爬虫的允许爬取的资源限制, 为空表示不限制。爬虫会自动添加扫描目标到 Hostname_allowed。"`
	BasicAuth            AuthCredential                `yaml:"basic_auth" json:"basic_auth" #:"基础认证信息"`
}

type Items struct {
	Item []burpFlow `xml:"item"`
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
