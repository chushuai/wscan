/*
*
2 * @Author: shaochuyu
3 * @Date: 8/24/25
*/
package mcp

import (
	"context"
	"encoding/base64"
	"io"
	"strings"
	"wscan/core/collector"
	"wscan/core/collector/basiccrawler"
	"wscan/core/crawler"
	"wscan/core/ctrl"
	"wscan/core/output"
	logger "wscan/core/utils/log"
	"wscan/core/utils/printer"
)

func UrlScan(task *Task, mode string) error {
	var col collector.Fitter
	// 支持 basic-auth：如果配置了用户名密码且 headers 中没有 Authorization，自动注入
	// basic-crawler 和 browser-crawler 共用 crawler.basic_auth 配置
	if _, hasAuth := globalConfig.HTTP.DefaultHeaders["Authorization"]; !hasAuth && globalConfig.Crawler.BasicAuth.Username != "" {
		auth := base64.StdEncoding.EncodeToString([]byte(globalConfig.Crawler.BasicAuth.Username + ":" + globalConfig.Crawler.BasicAuth.Password))
		authHeader := "Basic " + auth
		globalConfig.HTTP.DefaultHeaders["Authorization"] = authHeader
		if globalConfig.HTTP.Headers == nil {
			globalConfig.HTTP.Headers = make(map[string][]string)
		}
		globalConfig.HTTP.Headers["Authorization"] = []string{authHeader}
	}
	if mode == "basic" {
		col = basiccrawler.NewBasicCrawlerCollector(globalConfig.HTTP, &crawler.Config{
			Proxy:         globalConfig.HTTP.Proxy,
			Browser:       false,
			MaxConcurrent: 5,
			MaxDepth:      globalConfig.Crawler.BasicCrawler.MaxDepth,
			Restrictions:  globalConfig.Crawler.Restriction,
		})
	} else if mode == "browser" {
		// MaxPageConcurrent/MaxDepth/MaxPageVisit 默认值为 0，需要兜底
		maxPageConcurrent := globalConfig.Crawler.BrowserConfig.MaxPageConcurrent
		if maxPageConcurrent <= 0 {
			maxPageConcurrent = 5
		}
		maxDepth := globalConfig.Crawler.BrowserConfig.MaxDepth
		if maxDepth <= 0 {
			maxDepth = 10
		}
		maxPageVisit := globalConfig.Crawler.BrowserConfig.MaxPageVisit
		if maxPageVisit <= 0 {
			maxPageVisit = 200
		}
		col = basiccrawler.NewBasicCrawlerCollector(globalConfig.HTTP, &crawler.Config{
			Proxy:           globalConfig.HTTP.Proxy,
			ExecPath:        globalConfig.Crawler.BrowserConfig.ExecPath,
			DisableHeadless: globalConfig.Crawler.BrowserConfig.DisableHeadless,
			Browser:         true,
			MaxConcurrent:   maxPageConcurrent,
			MaxDepth:        maxDepth,
			MaxCountOfURLs:  maxPageVisit,
			Restrictions:    globalConfig.Crawler.Restriction,
		})
	} else {
		col = collector.NewFromURLListReader(io.NopCloser(strings.NewReader("")), globalConfig.HTTP)
	}
	logger.Infof("url scan task:%v crawler type %s", task.ScanUrl, mode)
	targets := []string{task.ScanUrl}
	var err error
	taskChan, err := col.FitOut(context.Background(), targets)
	if err != nil {
		logger.Fatal(err)
	}

	multiPrinter := printer.NewMultiPrinter()
	printers := []printer.Printer{}
	printers = append(printers, NewMcpPrinter(task))
	printers = append(printers, output.NewStdoutPrinter())
	multiPrinter.AddPrinters(printers)

	dispatcher := ctrl.NewDispatcher(&globalConfig.Config, multiPrinter, globalReverse)
	dispatcher.Init(false)
	dispatcher.Run(taskChan, false)
	dispatcher.Release()

	defer multiPrinter.Close()

	logger.Infof("task name %s  id %s finished", task.Name, task.ID)
	return nil
}
