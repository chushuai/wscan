/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package crawler

import (
	"context"
	"github.com/PuerkitoBio/goquery"
	"net/http"
	"net/url"
	"sync"
)

type selectorChecker struct {
	usedSelectors sync.Map
	allSelectors  sync.Map
	clickCount    int64
	maxClick      int64
	nodesEvents   []NodeEvents
}

func (*selectorChecker) findNewNodesEvent() {

}

func (*selectorChecker) isUsedSelector(string, bool) bool {
	return false
}

func (*selectorChecker) countClick() {

}

func (*selectorChecker) shouldClick() bool {
	return false
}

// func (*Crawler) clickAndAnalyzePage()
func (c *Crawler) clickAndAnalyzePage(ctx context.Context, u *url.URL, doc *goquery.Document, res *http.Response, depth int) error {
	// 解析网页
	//page := &HTMLPage{
	//	URL:     u,
	//	Headers: res.Header,
	//}
	//page.ParseHTML(doc)
	//
	//// 检查是否需要进行点击操作
	//if !c.ClickChecker.ShouldClick(page) {
	//	return nil
	//}
	//
	//// 创建一个新的浏览器会话
	//browser, err := c.BrowserPool.NewBrowser(ctx, u)
	//if err != nil {
	//	return err
	//}
	//defer browser.Close()
	//
	//// 执行所有需要点击的操作，并分析点击后的网页
	//for _, clickSelector := range c.ClickChecker.GetClickSelectors(page) {
	//	clicked, err := browser.ClickAndWaitForNavigation(ctx, clickSelector)
	//	if err != nil {
	//		log.Printf("Failed to click element with selector %q: %v", clickSelector, err)
	//		continue
	//	}
	//
	//	clickedURL := clicked.URL
	//	if clickedURL == nil {
	//		continue
	//	}
	//
	//	// 判断是否需要创建新任务
	//	if c.shouldCreateNewTask(page, clickedURL, depth) {
	//		if err := c.addNewTask(clickedURL.String()); err != nil {
	//			log.Printf("Failed to create new task for URL %q: %v", clickedURL.String(), err)
	//		}
	//	}
	//}

	return nil
}
func (*Crawler) handleBrowserTask() {

}

func (*Crawler) findURLAndCreateNewTask() {

}

func (*Crawler) createTaskByURL() {

}
