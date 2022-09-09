/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package ctrl

import (
	"wscan/core/assassin/collector"
	"wscan/core/assassin/http"
	"wscan/core/assassin/plugins/base"
	"wscan/core/assassin/reverse"
	"wscan/core/utils/checker"
	"wscan/core/utils/log"
)

type Config struct {
	Parallel int                                   `json:"parallel" yaml:"parallel" #:"漏洞探测的 worker 数量，可以简单理解为同时有 50 个 POC 在运行"`
	HTTP     *http.ClientOptions                   `json:"http" yaml:"http"`
	Reverse  *reverse.Config                       `json:"reverse" yaml:"reverse"`
	Plugins  map[string]base.PluginConfigInterface `json:"plugins" yaml:"-"`
	Fingers  []string                              `json:"fingers" yaml:"-"`
	Filter   *checker.RequestCheckerConfig         `json:"filter" yaml:"-"`
	Log      *log.Config                           `json:"log" yaml:"-"`
	Queue    *collector.MitmQueueConfig            `json:"queue" yaml:"-"`
}

func NewDefaultConfig() Config {
	config := Config{
		Parallel: 30,
		HTTP: &http.ClientOptions{
			DialTimeout:     5,
			ReadTimeout:     10,
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
			HEADER_NO_USE: map[string]string{
				"User-Agent": "User-Agent: Mozilla/5.0 (Windows NT 10.0; rv:78.0) Gecko/20100101 Firefox/78.0",
			},
		},
		Reverse: &reverse.Config{},
		Filter:  &checker.RequestCheckerConfig{},
		Log:     &log.Config{},
		Queue:   &collector.MitmQueueConfig{},
	}
	return config
}
