/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package entry

import (
	"fmt"
	"github.com/urfave/cli/v2"
	"go.uber.org/automaxprocs/maxprocs"
	"gopkg.in/yaml.v3"
	"io/ioutil"
	"wscan/core/assassin/collector/basiccrawler"
	"wscan/core/assassin/http"
	"wscan/core/assassin/utils"
	"wscan/core/utils/log"
)

func NewApp(c *cli.Context) {
	fmt.Println(c.Bool("list"))
	fmt.Println(c.String("listen"))
	fmt.Println(c.Bool("basic-crawler"))
	fmt.Println(c.String("browser-crawler"))
	fmt.Println(c.String("poc"))
	utils.ColorPrintln("please download the binary manually. https://github.com/chaitin/rad/releases")
	log.GetLogger("phantasm")
	fmt.Println(c.String("dump-config"))
	fmt.Println(c.Bool("list"))
	fmt.Println(c.String("listen"))
	fmt.Println(c.Bool("basic-crawler"))
	fmt.Println(c.String("browser-crawler"))
	fmt.Println(c.String("config"))

	cfg, err := LoadOrGenConfig(c)
	if err != nil {
		log.Fatal(err)
	}
	if c.Bool("dump-config") == true {
		log.Info("Dumping example config to ./config.yaml.example")
	}
	maxprocs.Set()
	fmt.Println(cfg)
	basiccrawler.NewBasicCrawlerCollector()
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
		log.Infof(string(cfgData))
		err = yaml.Unmarshal(cfgData, &cfg)
		if err != nil {
			log.Error(err)
			return nil, err
		}
	}

	logLevel := c.String("log-level")
	if logLevel != "" {
		// cfg.LogLevel = logLevel
	}
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
