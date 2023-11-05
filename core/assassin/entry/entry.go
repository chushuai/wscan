/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package entry

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/urfave/cli/v2"
	"go.uber.org/automaxprocs/maxprocs"
	"gopkg.in/yaml.v3"
	"io/ioutil"
	"wscan/core/assassin/collector"
	"wscan/core/assassin/collector/basiccrawler"
	"wscan/core/assassin/ctrl"
	"wscan/core/assassin/http"
	"wscan/core/assassin/plugins"
	"wscan/core/assassin/plugins/base"
	"wscan/core/assassin/utils"
	"wscan/core/utils/checker"
	"wscan/core/utils/log"
	"wscan/ext/crawler"
)

func NewApp(c *cli.Context) {
	cfg, err := LoadOrGenConfig(c)
	if err != nil {
		log.Fatal(err)
	}
	if c.Bool("dump-config") == true {
		log.Info("Dumping example config to ./config.yaml.example")
	}
	maxprocs.Set()
	var collector collector.Fitter
	if c.Bool("basic-crawler") == true {
		collector = basiccrawler.NewBasicCrawlerCollector(cfg.HTTP, &crawler.Config{
			RestrictionsOnRequests: crawler.RestrictionsOnRequests{MaxConcurrent: 5, MaxDepth: 0},
			Restrictions:           cfg.Filter,
		})
	} else if c.Bool("url") == true {
		for _, url := range c.Args().Slice() {
			log.Println(url)
		}
		return
	} else if c.String("listen") != "" {
		log.Println("listen=", c.String("listen"))
		return
	} else {
		log.Fatal("Warning: you should use --html-output, --webhook-output or --json-output to persist your scan result\n`url`, `listen`, `raw-request`, `url-file`, `basic-crawler` and `browser-crawler` must use one, try `--help` to see details")
	}
	taskChan, err := collector.FitOut(context.Background(), c.Args().Slice())
	if err != nil {
		log.Fatal(err)
	}
	dispatcher := ctrl.NewDispatcher(&cfg.Config)
	dispatcher.Init(false)
	dispatcher.Run(taskChan)
	dispatcher.Release()
}

func LoadOrGenConfig(c *cli.Context) (*CliEntryConfig, error) {
	configPath := c.String("config")
	if configPath == "" {
		configPath = "./config.yaml"
	}
	cfg := &CliEntryConfig{}
	if !utils.FileExists(configPath) {
		log.Info("Generate default configurations to config.yaml")
		cfg = NewExampleConfig()
		cfgData, err := yaml.Marshal(cfg)
		if err != nil {
			return nil, err
		}
		// Generate default config
		if err = ioutil.WriteFile("./config.yaml", cfgData, 0644); err != nil {
			log.Error("can't write default config to config.yaml, please check permission.")
			return nil, err
		}
	} else {
		cfgData, err := ioutil.ReadFile(configPath)
		if err != nil {
			log.Error(err)
			return nil, err
		}

		err = yaml.Unmarshal(cfgData, &cfg)
		if err != nil {
			log.Error(err)
			return nil, err
		}
		cfg.Config.Plugins = make(map[string]base.PluginConfigInterface)
		for _, p := range plugins.All() {
			pluginConfig := p.DefaultConfig()
			jsonData, err := json.Marshal(cfg.Plugins[pluginConfig.BaseConfig().Name])
			if err != nil {
				log.Error(err)
				continue
			}
			if err = json.Unmarshal(jsonData, pluginConfig); err != nil {
				log.Error(err)
				continue
			}
			cfg.Config.Plugins[pluginConfig.BaseConfig().Name] = pluginConfig
		}
	}

	cfg.Filter = &checker.RequestCheckerConfig{
		URLCheckerConfig: checker.URLCheckerConfig{
			SchemeAllowed:        []string{},
			SchemeDisallowed:     []string{},
			HostnameAllowed:      []string{},
			HostnameDisallowed:   []string{},
			TCPPortAllowed:       []string{},
			TCPPortDisallowed:    []string{},
			PathAllowed:          []string{},
			PathDisallowed:       []string{},
			PathSuffixAllowed:    []string{},
			PathSuffixDisallowed: []string{},
			QueryKeyAllowed:      []string{},
			QueryKeyDisallowed:   []string{},
			QueryRawAllowed:      []string{},
			QueryRawDisallowed:   []string{},
			FragmentAllowed:      []string{},
			FragmentDisallowed:   []string{},
			URLRegexAllowed:      []string{},
			URLRegexDisallowed:   []string{},
			URLGlobAllowed:       []string{},
			URLGlobDisallowed:    []string{},
		},
		MethodAllowed:     []string{},
		MethodDisallowed:  []string{},
		PostKeyAllowed:    []string{},
		PostKeyDisallowed: []string{},
	}

	logLevel := c.String("log-level")
	logCfg := log.NewDefaultConfig()
	if logLevel != "" {
		logCfg.Level = logLevel
	}
	log.SetConfig(&logCfg)
	clientOptions := http.ClientOptions{}
	clientOptions.WroteBack()
	cfg.Subdomain.WroteBack()
	return cfg, nil

}

func newJSONPrinter() {
	// CompleteOutputPath()
	// p := printer.NewJsonPrinter()
	// p.AddInterceptor()
}

func NewMultiPrinter() {

}

func CompleteOutputPath() {
	utils.TimeStampSecond()
	utils.DatetimePretty()
}

func init() {
	fmt.Println(`^badger_[0-9]{19}$`)
}
