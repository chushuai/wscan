/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package entry

import (
	"wscan/core/assassin/collector"
	"wscan/core/assassin/ctrl"
)

var aConfigYaml = "config.yaml"

type CliEntryConfig struct {
	ctrl.Config  `yaml:",inline" json:",inline"`
	Subdomain    SubdomainConfig                   `yaml:"subdomain" json:"subdomain"`
	Mitm         collector.MitmConfig              `yaml:"mitm" json:"mitm"`
	BasicCrawler collector.BasicCrawlerConfig      `yaml:"basic-crawler" json:"basic-crawler"`
	Plugins      map[string]map[string]interface{} `yaml:"plugins" json:"plugins"`
	Update       UpdateConfig                      `yaml:"update" json:"update"`
}

func NewSubdomainConfig() {

}

func NewExampleConfig() *CliEntryConfig {
	config := CliEntryConfig{
		Config: ctrl.NewDefaultConfig(),
	}
	return &config
}

func verifyFile() {

}

func rsaVerify() {

}

func getPrinters() {

}
