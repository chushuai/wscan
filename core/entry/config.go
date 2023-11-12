/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package entry

import (
	"github.com/urfave/cli/v2"
	"wscan/core/collector"
	"wscan/core/ctrl"
	"wscan/core/output"
	"wscan/core/utils/checker"
	"wscan/core/utils/log"
	"wscan/core/utils/printer"
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
		Mitm: collector.MitmConfig{
			CACert: "./ca.crt",
			CAKey:  "./ca.key",
			Queue: collector.MitmQueueConfig{
				MaxLength: 3000,
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

func getPrinters(c *cli.Context) (printers []printer.Printer) {
	if c.String("json-output") != "" {
		printers = append(printers, newJSONPrinter())
	}
	if c.String("html-output") != "" {
		printers = append(printers, output.NewHTMLFilePrinter())
	}
	if c.String("webhook-output") != "" {
		printers = append(printers, output.NewWebHookPrinter())
	}
	if len(printers) == 0 {
		log.Warnf("ou should use --html-output, --webhook-output or --json-output to persist your scan result")
	}
	printers = append(printers, output.NewStdoutPrinter())
	return
}
