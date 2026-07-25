/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package entry

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"wscan/core/collector"
	"wscan/core/collector/basiccrawler"
	"wscan/core/crawler"
	"wscan/core/ctrl"
	"wscan/core/plugins"
	"wscan/core/plugins/base"
	"wscan/core/plugins/prometheus"
	"wscan/core/reverse"
	"wscan/core/utils"
	"wscan/core/utils/checker"
	"wscan/core/utils/log"
	"wscan/core/utils/printer"

	"github.com/thoas/go-funk"
	"github.com/urfave/cli/v2"
	"go.uber.org/automaxprocs/maxprocs"
	"gopkg.in/yaml.v3"
)

func NewApp(c *cli.Context) error {
	cfg, err := LoadOrGenConfig(c)
	if err != nil {
		log.Fatal(err)
	}
	if c.Bool("dump-config") {
		log.Info("Dumping example config to ./config.yaml.example")
	}
	maxprocs.Set()
	var col collector.Fitter
	targets := []string{}
	fmt.Println(c.Args())
	if c.Bool("list") {
		for _, p := range plugins.All() {
			fmt.Printf("[+] %s\n", p.DefaultConfig().BaseConfig().Name)
		}
		os.Exit(0)
	}

	// 支持 basic-auth：如果配置了用户名密码且 headers 中没有 Authorization，自动注入
	// basic-crawler 和 browser-crawler 共用 crawler.basic_auth 配置
	if _, hasAuth := cfg.HTTP.DefaultHeaders["Authorization"]; !hasAuth && cfg.Crawler.BasicAuth.Username != "" {
		auth := base64.StdEncoding.EncodeToString([]byte(cfg.Crawler.BasicAuth.Username + ":" + cfg.Crawler.BasicAuth.Password))
		authHeader := "Basic " + auth
		cfg.HTTP.DefaultHeaders["Authorization"] = authHeader
		if cfg.HTTP.Headers == nil {
			cfg.HTTP.Headers = make(map[string][]string)
		}
		cfg.HTTP.Headers["Authorization"] = []string{authHeader}
	}

	if c.String("burp-file") != "" {
		// Burp Suite 导出文件处理
		log.Infof("Using Burp File: %s", c.String("burp-file"))
		burpData, err := os.ReadFile(c.String("burp-file"))
		if err != nil {
			log.Fatal(err)
		}
		col = collector.NewFromBurpFile(burpData, cfg.HTTP)
	} else if c.String("raw-request") != "" {
		// 原始 HTTP 请求文件处理
		log.Infof("Using Raw Request File: %s", c.String("raw-request"))
		rawData, err := os.ReadFile(c.String("raw-request"))
		if err != nil {
			log.Fatal(err)
		}
		col = collector.NewFromRawRequestFile(rawData, c.Bool("force-ssl"), cfg.HTTP)
	} else if c.String("url") != "" || c.String("url-file") != "" {
		if c.String("url-file") != "" {
			log.Infof("Using  URL File: %s", c.String("url-file"))
			urlFile, err := os.Open(c.String("url-file"))
			if err != nil {
				log.Fatal(err)
			}
			defer urlFile.Close()
			scanner := bufio.NewScanner(urlFile)
			for scanner.Scan() {
				url := strings.TrimSpace(scanner.Text())
				if url != "" && !funk.ContainsString(targets, url) {
					targets = append(targets, url)
				}
			}
		} else {
			log.Infof("Using  URL: %s", c.String("url"))
			targets = append(targets, c.String("url"))
		}
		if c.Bool("basic-crawler") {
			col = basiccrawler.NewBasicCrawlerCollector(cfg.HTTP, &crawler.Config{
				Proxy:                cfg.HTTP.Proxy,
				Browser:              false,
				MaxConcurrent:        5,
				MaxDepth:             cfg.Crawler.BasicCrawler.MaxDepth,
				Restrictions:         cfg.Crawler.Restriction,
				AllowVisitParentPath: cfg.Crawler.BasicCrawler.AllowVisitParentPath,
			})
		} else if c.Bool("browser-crawler") {
			// MaxPageConcurrent/MaxDepth/MaxPageVisit 默认值为 0，需要兜底
			maxPageConcurrent := cfg.Crawler.BrowserConfig.MaxPageConcurrent
			if maxPageConcurrent <= 0 {
				maxPageConcurrent = 5
			}
			maxDepth := cfg.Crawler.BrowserConfig.MaxDepth
			if maxDepth <= 0 {
				maxDepth = 10
			}
			maxPageVisit := cfg.Crawler.BrowserConfig.MaxPageVisit
			if maxPageVisit <= 0 {
				maxPageVisit = 200
			}
			col = basiccrawler.NewBasicCrawlerCollector(cfg.HTTP, &crawler.Config{
				Proxy:                    cfg.HTTP.Proxy,
				ExecPath:                 cfg.Crawler.BrowserConfig.ExecPath,
				DisableHeadless:          cfg.Crawler.BrowserConfig.DisableHeadless,
				Browser:                  true,
				MaxConcurrent:            maxPageConcurrent,
				MaxDepth:                 maxDepth,
				MaxCountOfURLs:           maxPageVisit,
				Restrictions:             cfg.Crawler.Restriction,
				ForceSandbox:             cfg.Crawler.BrowserConfig.ForceSandbox,
				WindowWidth:              cfg.Crawler.BrowserConfig.Width,
				WindowHeight:             cfg.Crawler.BrowserConfig.Height,
				NavigateTimeoutSecond:    cfg.Crawler.BrowserConfig.NavigateTimeoutSecond,
				LoadTimeoutSecond:        cfg.Crawler.BrowserConfig.LoadTimeoutSecond,
				Retry:                    cfg.Crawler.BrowserConfig.Retry,
				PageAnalyzeTimeoutSecond: cfg.Crawler.BrowserConfig.PageAnalyzeTimeoutSecond,
				MaxInteractive:           cfg.Crawler.BrowserConfig.MaxInteractive,
				MaxInteractiveDepth:      cfg.Crawler.BrowserConfig.MaxInteractiveDepth,
				MaxPageVisitPerSite:      cfg.Crawler.BrowserConfig.MaxPageVisitPerSite,
				ElementFilterStrength:    int(cfg.Crawler.BrowserConfig.ElementFilterStrength),
				ParentPathDetect:         cfg.Crawler.BrowserConfig.ParentPathDetect,
				TabInitJS:                cfg.Crawler.BrowserConfig.TabInitJS,
			})
		} else {
			col = collector.NewFromURLListReader(io.NopCloser(strings.NewReader(c.String("data"))), cfg.HTTP)
		}

	} else if c.String("listen") != "" {
		log.Println("listen=", c.String("listen"))
		cfg.Mitm.Listen = c.String("listen")
		col = collector.NewMitmProxy(&cfg.Mitm, cfg.HTTP)
	} else {
		log.Fatal("Warning: you should use --html-output, --webhook-output or --json-output to persist your scan result\n`url` `url-file`,`listen` must use one, try `--help` to see details")
	}
	taskChan, err := col.FitOut(context.Background(), targets)
	if err != nil {
		log.Fatal(err)
	}

	multiPrinter := printer.NewMultiPrinter()
	printers := getPrinters(c)
	multiPrinter.AddPrinters(printers)
	dispatcher := ctrl.NewDispatcher(&cfg.Config, multiPrinter, reverse.NewReverse(cfg.Reverse))
	dispatcher.Init(false)

	dispatcher.Run(taskChan, c.Bool("no-scan"))
	dispatcher.Release()

	defer multiPrinter.Close()

	return nil
}

func LoadOrGenConfig(c *cli.Context) (*CliEntryConfig, error) {
	configPath := c.String("config")
	if configPath == "" {
		configPath = "./config.yaml"
	}
	cfg := &CliEntryConfig{}
	exampleCfg := NewExampleConfig()
	if !utils.FileExists(configPath) {
		log.Info("Generate default configurations to config.yaml")
		cfg = exampleCfg
		if err := cfg.Dump("./config.yaml"); err != nil {
			log.Fatal(err.Error())
			return nil, err
		}
	} else {
		if c == nil {
			return nil, nil
		}
		cfgData, err := os.ReadFile(configPath)
		if err != nil {
			log.Fatal(err)
			return nil, err
		}

		err = yaml.Unmarshal(cfgData, &cfg)
		if err != nil {
			log.Fatal(err)
			return nil, err
		}
		if cfg.Version != exampleCfg.Version {
			if err = cfg.Dump(fmt.Sprintf("%s_%s_old", configPath, cfg.Version)); err != nil {
				log.Fatal("can't write default config to config.yaml, please check permission.")
				return nil, err
			}
			cfg = exampleCfg
			if err = cfg.Dump(configPath); err != nil {
				log.Fatal(err.Error())
				return nil, err
			}
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

	if c.String("poc") != "" {
		for name, pc := range cfg.Config.Plugins {
			log.Infof("%s-%v", name, pc)
			if name == "prometheus" {
				pc.BaseConfig().Enabled = true
				jsonData, _ := json.Marshal(pc)
				prometheusConfig := &prometheus.Config{}
				json.Unmarshal(jsonData, prometheusConfig)
				prometheusConfig.POC = []string{c.String("poc")}
				cfg.Config.Plugins[name] = prometheusConfig

			} else {
				pc.BaseConfig().Enabled = false
			}
		}
	} else if c.String("plugins") != "" {
		enabledPlugins := strings.Split(c.String("plugins"), ",")
		for name, pc := range cfg.Config.Plugins {
			if funk.ContainsString(enabledPlugins, name) {
				pc.BaseConfig().Enabled = true
			} else {
				pc.BaseConfig().Enabled = false
			}
		}
	}

	if c.String("basic-crawler") != "" {
		cfg.Filter = cfg.Crawler.Restriction
	} else if c.String("browser-crawler") != "" {
		cfg.Filter = cfg.Crawler.Restriction
	} else {
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
	}

	logLevel := c.String("log-level")
	logCfg := log.NewDefaultConfig()
	if logLevel != "" {
		logCfg.Level = logLevel
	}
	log.SetConfig(&logCfg)

	// Apply CLI vuln filter flags
	if c.String("min-severity") != "" {
		cfg.VulnFilter.MinSeverity = c.String("min-severity")
	}
	if c.String("exclude-vuln") != "" {
		cfg.VulnFilter.ExcludeVulns = strings.Split(c.String("exclude-vuln"), ",")
	}
	if c.String("include-vuln") != "" {
		cfg.VulnFilter.IncludeVulns = strings.Split(c.String("include-vuln"), ",")
	}

	cfg.HTTP.WroteBack()
	cfg.HTTP.TLSSkipVerify = true
	return cfg, nil

}
