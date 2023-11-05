/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package crawler

import (
	"github.com/PuerkitoBio/goquery"
	"golang.org/x/net/context"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"
	"wscan/core/utils/checker"
	"wscan/core/utils/collections"
	"wscan/core/utils/log"
)

type Crawler struct {
	CrawlerStatistic
	Client                  *Client
	filter                  Filter
	config                  *Config
	logger                  *log.Logger
	ctx                     context.Context
	cancel                  func()
	wg                      sync.WaitGroup
	taskChan                chan *task
	taskQueue               *collections.Queue
	feedEnded               bool
	entranceURLs            sync.Map
	allURLs                 sync.Map
	visitedURLs             sync.Map
	requestHandlers         []func(*http.Request) bool
	notVisitRequestHandlers []func(*http.Request, error)
	responseHandlers        []func(*http.Response) bool
	documentHandlers        []func(*url.URL, *goquery.Document, *http.Response, int) bool
	errorHandlers           []func(error)
	newURLsHandlers         []func(string)
	requestHandlersMutex    sync.Mutex
	responseHandlersMutex   sync.Mutex
	documentHandlersMutex   sync.Mutex
	errorHandlersMutex      sync.Mutex
	newTaskMutex            sync.Mutex
	newURLsHandlersMutex    sync.Mutex
	workingTasks            []*task
	chromeCtx               context.Context
	targetIDs               sync.Map
	tabLock                 sync.Mutex
	pkcs12File              *os.File
	tempFileForUpload       *os.File
	urlChecker              *checker.URLChecker
}

type task struct {
	req           *http.Request
	ireq          *http.Request
	redirectCount int
	depth         int
}

func NewCrawler(config *Config, urlChecker *checker.URLChecker) *Crawler {
	crawler := &Crawler{
		logger:     log.GetLogger("crawler"),
		config:     config,
		taskQueue:  collections.NewQueue(),
		taskChan:   make(chan *task, 100),
		urlChecker: urlChecker,
	}
	crawler.ctx, crawler.cancel = context.WithCancel(context.Background())
	if client, err := NewClient(&ClientConfig{
		DialTimeout:         10,
		TLSHandshakeTimeout: 10,
		ReadTimeout:         10,
		IdleConnTimeout:     10,
		MaxConnsPerHost:     10,
		MaxIdleConns:        10,
		TLSSkipVerify:       false,
	}); err == nil {
		crawler.Client = client
	} else {
		log.Fatal(err)
	}
	return crawler
}

func (c *Crawler) AvailabilityCheck() {
	//if _, err := c.Client.Do(c.config.StartURL); err != nil {
	//	c.logger.Printf("failed to connect to %s, error: %v", c.config.StartURL, err)
	//} else {
	//	c.logger.Printf("successfully connected to %s", c.config.StartURL)
	//}
}

func (c *Crawler) EndFeed() {
	c.feedEnded = true
}

func (c *Crawler) Feed() {
	for c.feedEnded == false {
		if c.taskQueue.Len() != 0 {
			c.taskChan <- c.taskQueue.TryPop().(*task)
		} else {
			time.Sleep(1 * time.Second)
		}
	}
	return
}

func (c *Crawler) GetStatistic() CrawlerStatistic {
	return c.CrawlerStatistic
}

func (*Crawler) Login(context.Context) error {
	return nil
}

func (c *Crawler) NewTask(req *http.Request, depth int) {
	if req == nil {
		c.logger.Println("Invalid request.")
		return
	}
	// 通过检查器检查URL是否合法
	if !c.urlChecker.TargetStr(req.URL.String()).IsAllowed() {
		c.logger.Printf("URL is invalid: %s\n", req.URL.String())
		return
	}

	if _, exist := c.visitedURLs.Load(req.URL.String()); exist {
		c.logger.Printf("URL is visited: %s\n", req.URL.String())
		return
	}
	c.visitedURLs.Store(req.URL.String(), struct{}{})
	// 新建一个任务
	t := &task{
		req:           req,
		redirectCount: 0,
		depth:         depth,
	}
	c.wg.Add(1)
	// 将任务添加到任务队列中
	c.taskQueue.PushBack(t)

	c.logger.Printf("New task added: %s\n", t.req.URL.String())
}

func (c *Crawler) OnError(handler func(err error)) {
	c.errorHandlersMutex.Lock()
	defer c.errorHandlersMutex.Unlock()

	c.errorHandlers = append(c.errorHandlers, handler)
}

// func (*Crawler) OnNewURLs()
func (c *Crawler) OnNewURLs(handler func(string)) {
	c.newURLsHandlersMutex.Lock()
	defer c.newURLsHandlersMutex.Unlock()
	c.newURLsHandlers = append(c.newURLsHandlers, handler)
}

func (c *Crawler) OnRequest(handler func(req *http.Request) bool) {
	c.requestHandlersMutex.Lock()
	defer c.requestHandlersMutex.Unlock()
	c.requestHandlers = append(c.requestHandlers, handler)
}

// func (*Crawler) OnRequestNotVisit()
func (c *Crawler) OnRequestNotVisit(handler func(*http.Request, error)) {
	c.requestHandlersMutex.Lock()
	defer c.requestHandlersMutex.Unlock()
	c.notVisitRequestHandlers = append(c.notVisitRequestHandlers, handler)
	return
}

// func (*Crawler) OnResponse()
func (c *Crawler) OnResponse(handler func(*http.Response) bool) {
	c.responseHandlersMutex.Lock()
	defer c.responseHandlersMutex.Unlock()
	c.responseHandlers = append(c.responseHandlers, handler)
}

func (c *Crawler) handleDocument(u *url.URL, doc *goquery.Document, resp *http.Response, depth int) bool {
	// 创建一个选择器检查器
	c.documentHandlersMutex.Lock()
	defer c.documentHandlersMutex.Unlock()
	for _, handler := range c.documentHandlers {
		handler(u, doc, resp, depth)
	}
	return false
}

func (c *Crawler) handleErr(e error) {
	c.errorHandlersMutex.Lock()
	defer c.errorHandlersMutex.Unlock()
	for _, handler := range c.errorHandlers {
		handler(e)
	}
}

func (c *Crawler) handleNewURLs(newURL string) {
	c.newURLsHandlersMutex.Lock()
	defer c.newURLsHandlersMutex.Unlock()
	for _, handler := range c.newURLsHandlers {
		handler(newURL)
	}
}

func (c *Crawler) handleReq(r *http.Request) bool {
	c.requestHandlersMutex.Lock()
	defer c.requestHandlersMutex.Unlock()
	for _, handler := range c.requestHandlers {
		if handler(r) == false {
			return false
		}
	}
	return true
}

func (c *Crawler) handleReqNotVisit(r *http.Request, e error) {
	c.requestHandlersMutex.Lock()
	defer c.requestHandlersMutex.Unlock()
	for _, handler := range c.notVisitRequestHandlers {
		handler(r, e)
	}
}

func (c *Crawler) handleResp(r *http.Response) bool {
	c.responseHandlersMutex.Lock()
	defer c.responseHandlersMutex.Unlock()
	for _, handler := range c.responseHandlers {
		if !handler(r) {
			return false
		}
	}
	return true
}

func (c *Crawler) Pause(string) error {
	return nil
}

func (*Crawler) Recover(string) error {
	return nil
}

func (c *Crawler) Run() {
	// 关闭 pkcs12 文件
	if c.pkcs12File != nil {
		_ = c.pkcs12File.Close()
	}

	for i := 0; i < c.config.MaxConcurrent; i++ {
		go c.newWorker(i)
	}
	go c.Feed()
}

func (c *Crawler) Stop() {
	c.cancel()
}

func (c *Crawler) Wait() {
	c.wg.Wait()
	c.feedEnded = true
	c.Stop()
	c.logger.Infof("Crawler End")
}

func (*Crawler) clear() {

}

func (c *Crawler) handleTask(t *task) {

	// 发送 HTTP 请求
	resp, err := c.Client.Do(t.req)
	if err != nil {
		// 处理错误
		c.handleErr(err)
		return
	}
	defer resp.Body.Close()
	c.handleResp(resp)

	// 处理响应的 HTML 文档
	doc, err := goquery.NewDocumentFromReader(resp.Body)
	if err != nil {
		// 处理错误
		c.handleErr(err)
		return
	}
	u := t.req.URL

	// 调用处理函数处理 HTML 文档
	if c.handleDocument(u, doc, resp, t.depth) {
		// 如果处理函数返回 true，则说明该任务已经完成了，不再需要处理
		return
	}

	// 判断是否需要继续遍历页面链接
	if t.depth < c.config.MaxDepth || c.config.MaxDepth == 0 {
		links := []string{} // ExtractLinks(resp.Body, t.req.URL)

		doc.Find("a").Each(func(i int, q *goquery.Selection) {
			href, exists := q.Attr("href")
			if exists {
				if newUrl, err := resp.Request.URL.Parse(href); err == nil {
					links = append(links, newUrl.String())
				}
			}
		})
		for _, link := range links {
			// 构建新的请求对象
			req, err := http.NewRequest("GET", link, nil)
			if err != nil {
				// 处理请求构建错误
				c.handleErr(err)
				continue
			}

			// 复制原请求对象的Header信息
			for k, v := range t.req.Header {
				req.Header[k] = v
			}

			// 判断请求是否需要进一步处理
			skip := false
			if !c.handleReq(req) {
				skip = true
			}

			if skip {
				continue
			}

			// 添加新的任务
			c.NewTask(req, t.depth+1)
		}
	}
}

func (c *Crawler) newWorker(id int) {
	c.logger.Printf("Worker #%d started\n", id)
	for {
		select {
		case <-c.ctx.Done():
			c.logger.Printf("Worker #%d stopped\n", id)
			return
		case t := <-c.taskChan:
			c.handleTask(t)
			c.wg.Done()
			//if c.visitedURLs.Load(t.req.URL.String()) != nil {
			//	continue
			//}
			//if c.filter != nil && !c.filter.Match(t.req.URL) {
			//	continue
			//}

			// 处理 request handlers
			//if !c.handleReq(t.req) {
			//	continue
			//}
			//
			//// 发送请求
			//resp, err := c.Client.Do(t.req)
			//
			//// 处理 request handlers for not visited
			//if err != nil {
			//	c.handleReqNotVisit(t.req, err)
			//}
			//
			//// 处理 response handlers
			//if !c.handleResp(resp) {
			//	resp.Body.Close()
			//	continue
			//}
		}
	}
}
