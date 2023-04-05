/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package entry

import (
	"fmt"
	"github.com/urfave/cli/v2"
	"wscan/core/assassin/collector"
	"wscan/core/assassin/ctrl"
	"wscan/core/utils/checker"
)

var aConfigYaml = "config.yaml"

type CliEntryConfig struct {
	ctrl.Config  `yaml:",inline" json:",inline"`
	Subdomain    SubdomainConfig              `yaml:"subdomain" json:"subdomain"`
	Mitm         collector.MitmConfig         `yaml:"mitm" json:"mitm"`
	BasicCrawler collector.BasicCrawlerConfig `yaml:"basic-crawler" json:"basic-crawler"`
	Plugins      map[string]interface{}       `yaml:"plugins" json:"plugins"`
	Update       UpdateConfig                 `yaml:"update" json:"update"`
}

func NewSubdomainConfig() SubdomainConfig {
	return SubdomainConfig{}
}

func NewExampleConfig() *CliEntryConfig {
	config := CliEntryConfig{
		Config:    ctrl.NewDefaultConfig(),
		Subdomain: NewSubdomainConfig(),
		BasicCrawler: collector.BasicCrawlerConfig{
			Restriction: &checker.RequestCheckerConfig{
				URLCheckerConfig: checker.URLCheckerConfig{
					HostnameDisallowed: []string{"*google*",
						"*github*", "*.gov.cn", "*.edu.cn",
					},
				},
			},
		},
		Plugins: make(map[string]interface{}),
	}
	for name, p := range config.Config.Plugins {
		config.Plugins[name] = p
	}
	return &config
}

func verifyFile() {

}

func rsaVerify() {

}

func getPrinters(c *cli.Context) {
	fmt.Println(c.String("text-output"))
	fmt.Println(c.String("json-output"))
	fmt.Println(c.String("html-output"))
	fmt.Println(c.String("webhook-output"))

}
