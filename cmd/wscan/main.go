/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package main

import (
	"flag"
	"fmt"
	"os"
	"wscan/core/entry"
	"wscan/core/mcp"
	"wscan/core/utils"
	logger "wscan/core/utils/log"
	"wscan/core/web"

	"github.com/fatih/color"
	"github.com/urfave/cli/v2"
	"gopkg.in/yaml.v3"
)

// init 清除 martian init.go 用 flag.Int("v") 在 flag.CommandLine 上注册的 -v 标志。
// urfave/cli 的 VersionFlag 也用 -v 别名,两者都向 flag.CommandLine 注册 "v" 会
// 触发 "flag redefined: v" panic。core/collector 的 init 会重建 flag.CommandLine,
// 但 collector 仅被部分包导入;main 包一定在所有被依赖包之后 init,在此兜底重建
// 一次 flag.CommandLine,确保无论 import 链如何,-v 冲突都被抹掉。
// setVersion 设置版本号
func setVersion() {
	utils.VersionInfo = "1.0.46"
}

// init 清除 martian init.go 用 flag.Int("v") 在 flag.CommandLine 上注册的 -v 标志。
// urfave/cli 的 VersionFlag 也用 -v 别名，两者都向 flag.CommandLine 注册 "v" 会
// 触发 "flag redefined: v" panic。core/collector 的 init 会重建 flag.CommandLine,
// 但 collector 仅被部分包导入;main 包一定在所有被依赖包之后 init,在此兜底重建
// 一次 flag.CommandLine，确保无论 import 链如何，-v 冲突都被抹掉。
func init() {
	setVersion()
	flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
}

func showBanner() {

	banner := `
██╗    ██╗███████╗ ██████╗ █████╗ ███╗   ██╗
██║    ██║██╔════╝██╔════╝██╔══██╗████╗  ██║
██║ █╗ ██║███████╗██║     ███████║██╔██╗ ██║
██║███╗██║╚════██║██║     ██╔══██║██║╚██╗██║
╚███╔███╔╝███████║╚██████╗██║  ██║██║ ╚████║
 ╚══╝╚══╝ ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
                                            
`
	fmt.Println(banner)
}

func GenerateCA(c *cli.Context) error {
	_, err := entry.LoadOrGenConfig(c)
	if err != nil {
		logger.Fatal(err)
	}
	if err := utils.GenerateCAToPath("." + string(os.PathSeparator)); err != nil {
		return err
	}
	color.Green("CA certificate ca.crt and key ca.key generated")
	return nil
}

func Version(c *cli.Context) error {
	return nil
}

var subCommandWebScan = cli.Command{
	Name:    "webscan",
	Aliases: []string{"ws"},
	Usage:   "Run a webscan task",
	Flags: []cli.Flag{
		&cli.BoolFlag{
			Name:    "list",
			Aliases: []string{"l"},
			Value:   false,
			Usage:   "list plugins"},
		&cli.StringFlag{
			Name:    "plugins",
			Aliases: []string{"plug"},
			Value:   "",
			Usage:   "specify the plugins to run, separated by ','"},
		&cli.StringFlag{
			Name:    "poc",
			Aliases: []string{"p"},
			Value:   "",
			Usage:   "specify the poc to run, separated by ',' "},
		&cli.StringFlag{
			Name:    "listen",
			Aliases: []string{},
			Value:   "",
			Usage:   "use proxy resource collector, value is proxy addr, (example: 127.0.0.1:1111)"},
		&cli.BoolFlag{
			Name:    "basic-crawler",
			Aliases: []string{"basic"},
			Value:   false,
			Usage:   "use a basic spider to crawl the target and scan the requests"},
		&cli.BoolFlag{
			Name:    "browser-crawler",
			Aliases: []string{"browser"},
			Value:   false,
			Usage:   "use a browser spider to crawl the target and scan the requests"},
		&cli.StringFlag{
			Name:    "url-file",
			Aliases: []string{"uf"},
			Value:   "",
			Usage:   "read urls from a local file and scan these urls, one url per line"},
		&cli.StringFlag{
			Name:    "burp-file",
			Aliases: []string{"bf"},
			Value:   "",
			Usage:   "read requests from burpsuite exported file as targets"},
		&cli.StringFlag{
			Name:    "url",
			Aliases: []string{"u"},
			Value:   "",
			Usage:   "scan a **single** url"},
		&cli.StringFlag{
			Name:    "data",
			Aliases: []string{"d"},
			Value:   "",
			Usage:   "data string to be sent through POST (e.g. 'username=admin')"},
		&cli.StringFlag{
			Name:    "raw-request",
			Aliases: []string{"rr"},
			Value:   "",
			Usage:   "load http raw request from a FILE"},
		&cli.BoolFlag{
			Name:    "force-ssl",
			Aliases: []string{"fs"},
			Value:   false,
			Usage:   "force usage of SSL/HTTPS for raw-request"},
		&cli.BoolFlag{
			Name:    "no-scan",
			Aliases: []string{"ns"},
			Value:   false,
			Usage:   "No vulnerability detection, only enable crawlers"},
		&cli.StringFlag{
			Name:    "json-crawler-output",
			Aliases: []string{"jco"},
			Value:   "",
			Usage:   "output wscan crawler results to FILE in json format"},
		&cli.StringFlag{
			Name:    "json-output",
			Aliases: []string{"jo"},
			Value:   "",
			Usage:   "output wscan results to FILE in json format"},
		&cli.StringFlag{
			Name:    "html-output",
			Aliases: []string{"ho"},
			Value:   "",
			Usage:   "output wscan result to FILE in HTML format"},
		&cli.StringFlag{
			Name:    "webhook-output",
			Aliases: []string{"wo"},
			Value:   "",
			Usage:   "post wscan result to url in json format"},
		&cli.StringFlag{
			Name:    "min-severity",
			Aliases: []string{"ms"},
			Value:   "",
			Usage:   "minimum severity level to display: info/low/medium/high/critical"},
		&cli.StringFlag{
			Name:    "exclude-vuln",
			Aliases: []string{"ev"},
			Value:   "",
			Usage:   "exclude vuln IDs, separated by ',' (supports glob)"},
		&cli.StringFlag{
			Name:    "include-vuln",
			Aliases: []string{"iv"},
			Value:   "",
			Usage:   "only scan these vuln IDs, separated by ',' (supports glob)"},
	},
	Action: entry.NewApp,
}

var subCommandReverse = cli.Command{
	Name:    "reverse",
	Aliases: []string{},
	Usage:   "Run a standalone reverse server",
	Flags:   []cli.Flag{},
	Action:  entry.ReverseAction,
}

var subCommandGenCA = cli.Command{
	Name:    "genca",
	Aliases: []string{},
	Usage:   "GenerateToFile CA certificate and key",
	Flags:   []cli.Flag{},
	Action:  GenerateCA,
}

var subCommandVersion = cli.Command{
	Name:    "version",
	Aliases: []string{},
	Usage:   "Show version info",
	Flags:   []cli.Flag{},
	Action:  Version,
}

func main() {
	showBanner()

	// 检查新版本
	utils.CheckNewVersion()

	// 程序启动时检测 config.yaml，不存在则自动生成默认配置
	if !utils.FileExists("config.yaml") {
		cfg := entry.NewExampleConfig()
		cfgData, err := yaml.Marshal(cfg)
		if err != nil {
			logger.Fatal("failed to marshal default config: " + err.Error())
		}
		if err = os.WriteFile("config.yaml", cfgData, 0644); err != nil {
			logger.Fatal("can't write default config to config.yaml, please check permission.")
		}
		logger.Info("Generate default configurations to config.yaml")
	}

	author := cli.Author{
		Name:  "shaochuyu",
		Email: "shaochuyu@qq.com",
	}
	app := &cli.App{
		Name:    "wscan",
		Usage:   "A powerful scanner engine ",
		Version: "1.0.46",
		Authors: []*cli.Author{&author},
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "config",
				Aliases: []string{},
				Value:   "",
				Usage:   "Load configuration from file (default to config. yaml)"},
			&cli.StringFlag{
				Name:    "log-level",
				Aliases: []string{},
				Value:   "",
				Usage:   "Log level, choices are debug, info, warn, error, fatal"},
		},
	}
	app.Commands = []*cli.Command{
		&subCommandWebScan,
		&subCommandReverse,
		&subCommandGenCA,
		&subCommandVersion,
		{
			Name:    "mcp",
			Aliases: []string{},
			Usage:   "Run mcp  server",
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:    "mcp-host",
					Aliases: []string{},
					Value:   "0.0.0.0",
					Usage:   "host to listen on"},
				&cli.IntFlag{
					Name:    "mcp-port",
					Aliases: []string{},
					Value:   7001,
					Usage:   "port to listen on"},
			},
			Action: func(context *cli.Context) error {
				mcp.StartMcpServer(context)
				return nil
			},
		},
		{
			Name:    "webui",
			Aliases: []string{},
			Usage:   "Run webui server (browser-based scan management)",
			Flags: []cli.Flag{
				&cli.StringFlag{
					Name:    "webui-host",
					Aliases: []string{},
					Value:   "0.0.0.0",
					Usage:   "host to listen on"},
				&cli.IntFlag{
					Name:    "webui-port",
					Aliases: []string{},
					Value:   7002,
					Usage:   "port to listen on"},
			},
			Action: func(context *cli.Context) error {
				return web.StartWebUIServer(context)
			},
		},
	}
	err := app.Run(os.Args)
	if err != nil {
		logger.Fatal(err.Error())
	}
}
