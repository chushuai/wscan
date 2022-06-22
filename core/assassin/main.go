/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package main

import (
	"fmt"
	"github.com/urfave/cli/v2"
	"os"
)

func Banner() string {

	banner := `
____  ___.________.    ____.   _____.___.
\   \/  /\_   __   \  /  _  \  \__  |   |
 \     /  |    _  _/ /  /_\  \  /   |   |
 /     \  |    |   \/    |    \ \____   |
\___/\  \ |____|   /\____|_   / / _____/
      \_/       \_/        \_/  \/

`
	return banner

}

func WebScan(c *cli.Context) error {
	return nil
}

func ServiceScan(c *cli.Context) error {
	return nil
}

func SubdomainScan(c *cli.Context) error {
	return nil
}

//   , sd    Run a subdomain task
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
	Flags:   []cli.Flag{},
	Action:  WebScan,
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
	fmt.Println(Banner())
	author := cli.Author{
		Name:  "shaochuyu",
		Email: "shaochuyu@qq.com",
	}
	app := &cli.App{
		Name:    "xray",
		Usage:   "A powerful scanner engine [https://docs.xray.cool]",
		Version: "1.8.4/a47961e0/COMMUNITY",
		Authors: []*cli.Author{&author},
		Flags:   []cli.Flag{},
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

func Run(c *cli.Context) error {
	return nil
}
