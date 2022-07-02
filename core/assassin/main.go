/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package main

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/google/martian/mitm"
	"github.com/urfave/cli/v2"
	"log"
	"os"
	"time"
)

func showBanner() {

	banner := `
____  ___.________.    ____.   _____.___.
\   \/  /\_   __   \  /  _  \  \__  |   |
 \     /  |    _  _/ /  /_\  \  /   |   |
 /     \  |    |   \/    |    \ \____   |
\___/\  \ |____|   /\____|_   / / _____/
      \_/       \_/        \_/  \/
`
	fmt.Println(banner)
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
	var err error
	x509c, priv, err := mitm.NewAuthority("martian.proxy", "Martian Authority", 365*24*time.Hour)
	if err != nil {
		log.Fatal(err)
	}
	//保存公钥私钥到当前目录上
	certOut, _ := os.Create("./server.pem")
	pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: x509c.Raw})
	certOut.Close()

	keyOut, _ := os.Create("./server.key")
	pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	keyOut.Close()
	fmt.Println("The Complete from Generating Certificat ")
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
	showBanner()
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

//aShowVersionInf

func loadLicense() {

}

func Run(c *cli.Context) error {
	return nil
}
