/**
2 * @Author: shaochuyu
3 * @Date: 8/30/22
4 */

package main

import (
	"fmt"
	"testing"
	"wscan/ext/crawlergo/pkg"
	"wscan/ext/crawlergo/pkg/config"
	"wscan/ext/crawlergo/pkg/model"
)

func TestCrawlergo(t *testing.T) {
	var taskConfig pkg.TaskConfig
	taskConfig.MaxTabsCount = 200
	taskConfig.MaxCrawlCount = 200
	taskConfig.NoHeadless = false
	var option model.Options
	var req model.Request
	url, err := model.GetUrl("https://docs.xray.cool/#/")
	if err != nil {
		// logger.Error("parse url failed, ", err)
		return
	}
	req = model.GetRequest(config.GET, url, option)
	task, err := pkg.NewCrawlerTask([]*model.Request{&req}, taskConfig)
	if err != nil {
		fmt.Println("create crawler task failed.")
		return
	}
	fmt.Println("Start crawling.")
	task.Run()
}
