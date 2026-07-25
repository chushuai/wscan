/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package ctrl

import (
	"wscan/core/collector"
	"wscan/core/http"
	"wscan/core/model"
	"wscan/core/plugins"
	"wscan/core/plugins/base"
	"wscan/core/reverse"
	"wscan/core/utils/checker"
	"wscan/core/utils/log"
)

// PostScanConfig controls the PostScan phase that runs after the main scan
// to verify whether injected payloads were persisted (stored XSS, stored SQLi, stored RCE).
type PostScanConfig struct {
	Enabled     bool `json:"enabled" yaml:"enabled" #:"是否启用 PostScan 阶段（存储型漏洞验证）"`
	MaxDuration int  `json:"max_duration" yaml:"max_duration" #:"PostScan 阶段最大持续时间（秒）"`
	ReverseWait int  `json:"reverse_wait" yaml:"reverse_wait" #:"等待 OOB 反连回调的时间（秒）"`
}

type Config struct {
	Version    string                                `json:"version" yaml:"version"`
	Parallel   int                                   `json:"parallel" yaml:"parallel" #:"漏洞探测的 worker 数量，可以简单理解为同时有 50 个 POC 在运行"`
	HTTP       *http.ClientOptions                   `json:"http" yaml:"http"`
	Reverse    *reverse.Config                       `json:"reverse" yaml:"reverse"`
	Plugins    map[string]base.PluginConfigInterface `json:"plugins" yaml:"-"`
	Fingers    []string                              `json:"fingers" yaml:"-"`
	Filter     *checker.RequestCheckerConfig         `json:"filter" yaml:"-"`
	Log        *log.Config                           `json:"log" yaml:"-"`
	Queue      *collector.MitmQueueConfig            `json:"queue" yaml:"-"`
	VulnFilter *model.VulnFilterConfig               `json:"vuln-filter" yaml:"vuln-filter"`
	PostScan   *PostScanConfig                       `json:"postscan" yaml:"postscan"`
}

func NewDefaultConfig() Config {
	config := Config{
		Version:  "1.14",
		Parallel: 30,
		HTTP: &http.ClientOptions{
			TLSSkipVerify:   true,
			DialTimeout:     5,
			ReadTimeout:     18,
			MaxConnsPerHost: 50,
			FailRetries:     0,
			MaxRedirect:     5,
			MaxRespBodySize: 2097152,
			MaxQPS:          500,
			AllowMethods: []string{
				"HEAD",
				"GET",
				"POST",
				"PUT",
				"PATCH",
				"DELETE",
				"OPTIONS",
				"CONNECT",
				"TRACE",
				"MOVE",
				"PROPFIND",
			},
			DefaultHeaders: map[string]string{
				"User-Agent": "Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0",
			},
		},
		Reverse: &reverse.Config{
			HTTPServerConfig: reverse.HTTPServerConfig{
				Enabled:    false,
				ListenIP:   "0.0.0.0",
				ListenPort: "",
				IPHeader:   "",
			},
			DNSServerConfig: reverse.DNSServerConfig{
				ListenIP: "0.0.0.0",
				Resolve: []reverse.ResolveConfig{
					{Type: "A", Record: "localhost", Value: "127.0.0.1", TTL: 60},
				},
			},
		},

		Filter:     &checker.RequestCheckerConfig{},
		Log:        &log.Config{},
		Queue:      &collector.MitmQueueConfig{},
		Plugins:    make(map[string]base.PluginConfigInterface),
		VulnFilter: &model.VulnFilterConfig{MinSeverity: "info"},
		PostScan: &PostScanConfig{
			Enabled:     true,
			MaxDuration: 60,
			ReverseWait: 120,
		},
	}
	plugins := plugins.All()
	for _, p := range plugins {
		d := p.DefaultConfig()
		config.Plugins[d.BaseConfig().Name] = d
	}
	return config
}
