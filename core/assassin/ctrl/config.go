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

func NewDefaultConfig() {

}

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
