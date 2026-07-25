/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package entry

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"wscan/core/collector"
	"wscan/core/ctrl"
	"wscan/core/model"
	"wscan/core/output"
	"wscan/core/plugins/base"
	"wscan/core/utils/checker"
	"wscan/core/utils/log"
	"wscan/core/utils/printer"

	"github.com/urfave/cli/v2"
	"gopkg.in/yaml.v3"
)

var aConfigYaml = "config.yaml"

type CliEntryConfig struct {
	ctrl.Config `yaml:",inline" json:",inline"`
	Crawler     collector.CrawlerCommonConfig `yaml:"crawler" json:"crawler"`
	Mitm        collector.MitmConfig          `yaml:"mitm" json:"mitm"`
	Plugins     map[string]any                `yaml:"plugins" json:"plugins"`
}

// Clone returns a deep-ish copy of the config: the top-level value is copied,
// and the per-plugin map is rebuilt so per-task enabled/proxy edits don't leak
// into the shared global config. The http.ClientOptions pointer is shared (it is
// only read for its schema by the crawler/dispatcher); callers that mutate proxy
// or headers must set a fresh copy first.
func (cc *CliEntryConfig) Clone() *CliEntryConfig {
	if cc == nil {
		return nil
	}
	out := *cc
	plugins := make(map[string]base.PluginConfigInterface, len(cc.Config.Plugins))
	for k, v := range cc.Config.Plugins {
		plugins[k] = v
	}
	out.Config.Plugins = plugins
	return &out
}

func (cc *CliEntryConfig) Dump(filePath string) error {
	cfgData, err := yaml.Marshal(cc)
	if err != nil {
		return err
	}
	if err = os.WriteFile(filePath, cfgData, 0644); err != nil {
		return errors.New(fmt.Sprintf("can't write default config to %s, please check permission.", filePath))
	}
	return nil
}

func NewExampleConfig() *CliEntryConfig {
	config := CliEntryConfig{
		Config: ctrl.NewDefaultConfig(),
		Crawler: collector.CrawlerCommonConfig{
			Restriction: &checker.RequestCheckerConfig{
				URLCheckerConfig: checker.URLCheckerConfig{
					HostnameDisallowed: []string{"*google*",
						"*github*", "*.gov.cn", "*.edu.cn",
					},
				},
			},
			BasicCrawler: collector.BasicCrawlerConfig{},
			BrowserConfig: collector.BrowserConfig{
				MaxDepth:                 10,
				NavigateTimeoutSecond:    10,
				LoadTimeoutSecond:        10,
				PageAnalyzeTimeoutSecond: 10,
				MaxPageConcurrent:        10,
				MaxPageVisitPerSite:      200,
				MaxPageVisit:             500,
				DisableHeadless:          false,
			},
		},
		Mitm: collector.MitmConfig{
			CACert: "./ca.crt",
			CAKey:  "./ca.key",
			Queue: collector.MitmQueueConfig{
				MaxLength: 3000,
			},
			Restriction: &checker.RequestCheckerConfig{
				URLCheckerConfig: checker.URLCheckerConfig{
					HostnameDisallowed: []string{"*google*",
						"*github*", "*.gov.cn", "*.edu.cn",
					},
				},
			},
		},

		Plugins: make(map[string]any),
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

// func(any) ([]byte, error){})

func getPrinters(c *cli.Context) (printers []printer.Printer) {
	if c.String("json-output") != "" {
		printers = append(printers, newJSONPrinter(c.String("json-output"), func(res any) ([]byte, error) {
			switch res.(type) {
			case *model.Vuln:
				vuln := res.(*model.Vuln)
				webVuln := vuln.ToWebVuln()
				return json.Marshal(webVuln)
			}
			return nil, nil
		}))
	}
	if c.String("json-crawler-output") != "" {
		printers = append(printers, newJSONPrinter(c.String("json-crawler-output"), func(res any) ([]byte, error) {
			switch res.(type) {
			case *model.CrawlerResult:
				return json.Marshal(res)
			}
			return nil, nil
		}))
	}
	if c.String("html-output") != "" {
		printers = append(printers, output.NewHTMLFilePrinter(c.String("html-output")))
	}
	if c.String("webhook-output") != "" {
		//  http.NewClientWithOptions(d.config.HTTP)
		u, err := url.Parse(c.String("webhook-output"))
		if err != nil {
			log.Error(err.Error())
		}
		printers = append(printers, output.NewWebHookPrinter(u))
	}
	if len(printers) == 0 {
		log.Warnf("you should use --html-output, --webhook-output or --json-output to persist your scan result")
	}
	printers = append(printers, output.NewStdoutPrinter())
	return
}
