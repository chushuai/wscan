/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package main

import (
	"fmt"
	"github.com/fatih/color"
	"github.com/urfave/cli/v2"
	"os"
	"wscan/core/entry"
	"wscan/core/utils"
)

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

func WebScan(c *cli.Context) error {
	entry.NewApp(c)
	return nil
}

func ServiceScan(c *cli.Context) error {
	return nil
}

func SubdomainScan(c *cli.Context) error {
	return nil
}

func PocLint(c *cli.Context) error {
	return nil
}

func Transform(c *cli.Context) error {
	return nil
}

func Reverse(c *cli.Context) error {
	return nil
}

func Convert(c *cli.Context) error {
	return nil
}

func GenerateCA(c *cli.Context) error {
	if err := utils.GenerateCAToPath("." + string(os.PathSeparator)); err != nil {
		return err
	}
	color.Green("CA certificate ca.crt and key ca.key generated")
	return nil
}

func Upgrade(c *cli.Context) error {
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
		&cli.StringFlag{
			Name:    "basic-crawler",
			Aliases: []string{"basic"},
			Value:   "",
			Usage:   "use a basic spider to crawl the target and scan the requests"},
		&cli.StringFlag{
			Name:    "browser-crawler",
			Aliases: []string{"browser"},
			Value:   "",
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
		&cli.StringFlag{
			Name:    "force-ssl",
			Aliases: []string{"fs"},
			Value:   "",
			Usage:   " force usage of SSL/HTTPS for raw-request"},
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
	},
	Action: WebScan,
}

var subCommandServiceScan = cli.Command{
	Name:    "servicescan",
	Aliases: []string{"ss"},
	Usage:   "Run a service scan task",
	Flags:   []cli.Flag{},
	Action:  ServiceScan,
}

var subCommandSubdomain = cli.Command{
	Name:    "subdomain",
	Aliases: []string{"sd"},
	Usage:   "Run a subdomain task",
	Flags:   []cli.Flag{},
	Action:  SubdomainScan,
}

var subCommandPocLint = cli.Command{
	Name:    "poclint",
	Aliases: []string{"pl"},
	Usage:   "lint yaml poc",
	Flags:   []cli.Flag{},
	Action:  PocLint,
}

var subCommandTransform = cli.Command{
	Name:    "transform",
	Aliases: []string{},
	Usage:   "transform other script to gamma",
	Flags:   []cli.Flag{},
	Action:  Transform,
}

var subCommandReverse = cli.Command{
	Name:    "reverse",
	Aliases: []string{},
	Usage:   "Run a standalone reverse server",
	Flags:   []cli.Flag{},
	Action:  Reverse,
}

var subCommandConvert = cli.Command{
	Name:    "convert",
	Aliases: []string{},
	Usage:   "convert results from json to html or from html to json",
	Flags:   []cli.Flag{},
	Action:  Convert,
}

var subCommandGenCA = cli.Command{
	Name:    "genca",
	Aliases: []string{},
	Usage:   "GenerateToFile CA certificate and key",
	Flags:   []cli.Flag{},
	Action:  GenerateCA,
}

var subCommandUpgrade = cli.Command{
	Name:    "upgrade",
	Aliases: []string{},
	Usage:   "check new version and upgrade self if any updates found",
	Flags:   []cli.Flag{},
	Action:  Upgrade,
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
	author := cli.Author{
		Name:  "shaochuyu",
		Email: "shaochuyu@qq.com",
	}
	app := &cli.App{
		Name:    "wscan",
		Usage:   "A powerful scanner engine ",
		Version: "1.0.9",
		Authors: []*cli.Author{&author},
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:    "config",
				Aliases: []string{},
				Value:   "",
				Usage:   "从文件中加载配置（默认为“config.yaml”）"},
			&cli.StringFlag{
				Name:    "log-level",
				Aliases: []string{},
				Value:   "",
				Usage:   "Log level, choices are debug, info, warn, error, fatal"},
		},
	}
	app.Commands = []*cli.Command{
		&subCommandWebScan,
		&subCommandServiceScan,
		&subCommandSubdomain,
		&subCommandPocLint,
		&subCommandTransform,
		&subCommandReverse,
		&subCommandConvert,
		&subCommandGenCA,
		&subCommandUpgrade,
		&subCommandVersion,
	}
	err := app.Run(os.Args)
	if err != nil {

	}
}

func loadLicense() {

}

func Run(c *cli.Context) error {
	return nil
}
