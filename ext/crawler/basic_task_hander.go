/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package crawler

import (
	"github.com/PuerkitoBio/goquery"
)

func (c *Crawler) handleBasicTask(t *task) {
	// 过滤URL
	if !c.filter.Check(t.req.URL.String(), true) {
		return
	}

	// 发送请求
	resp, err := c.Client.Do(t.req)
	if err != nil {
		for _, errorHandler := range c.notVisitRequestHandlers {
			errorHandler(t.req, err)
		}
		return
	}
	// defer resp.Body.Close()

	// 处理响应
	for _, responseHandler := range c.responseHandlers {
		if !responseHandler(resp) {
			return
		}
	}

	// 解析HTML文档
	//if resp.GetEncoding() == "text/html" {
	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		for _, errorHandler := range c.errorHandlers {
			errorHandler(err)
		}
		return
	}
	if c.handleDocument(t.req.URL, doc, resp, t.depth) {
		return
	}
	//}

	// 分析新URL并创建新任务
	c.findURLAndCreateNewTask()
}

func (*Crawler) do() {

}
