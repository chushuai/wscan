/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package crawler

import (
	"fmt"
	"net/url"
	"os"
	"sync"
	"time"
	"wscan/core/http"
	"wscan/core/utils/checker"
	"wscan/core/utils/collections"
	logger "wscan/core/utils/log"

	"github.com/PuerkitoBio/goquery"
	"github.com/chromedp/cdproto/cdp"
	"github.com/panjf2000/ants/v2"
	"golang.org/x/net/context"
)

type Crawler struct {
	CrawlerStatistic
	Client                  *http.Client
	filter                  Filter
	config                  *Config
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
	flowHandlers            []func(flow *http.Flow) bool
	documentHandlers        []func(*url.URL, *goquery.Document, *http.Response, int) bool
	errorHandlers           []func(error)
	newURLsHandlers         []func(string)
	flowHandlersMutex       sync.Mutex
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
	tempFileForUpload       *os.File
	urlChecker              *checker.URLChecker
	bro                     *Browser
	Browser                 *Browser        //
	RootDomain              string          // 当前爬取根域名 用于子域名收集
	Targets                 []*http.Request // 输入目标
	smartFilter             SmartFilter     // 过滤对象
	Pool                    *ants.Pool      // 协程池
	taskWG                  sync.WaitGroup  // 等待协程池所有任务结束
	crawledCount            map[string]int  // 爬取过的数量
	crawledCountLock        sync.Mutex
	taskCountLock           sync.Mutex // 已爬取的任务总数锁
	requestFilter           *checker.RequestChecker
	httpClient              *http.Client
}

type task struct {
	req           *http.Request
	ireq          *http.Request
	redirectCount int
	depth         int

	crawlerTask *Crawler
	browser     *Browser

	pool *ants.Pool

	Ctx                        *context.Context
	Cancel                     context.CancelFunc
	NavigateReq                http.Request
	NavigateReqRedirectionFlag bool
	ExtraHeaders               map[string]any
	TopFrameId                 string
	LoaderID                   string
	NavNetworkID               string
	PageCharset                string
	PageBindings               map[string]any
	NavDone                    chan int
	FoundRedirection           bool
	DocBodyNodeId              cdp.NodeID
	config                     TabConfig
	lock                       sync.Mutex
	WG                         sync.WaitGroup //当前Tab页的等待同步计数
	collectLinkWG              sync.WaitGroup
	loadedWG                   sync.WaitGroup //Loaded之后的等待计数
	formSubmitWG               sync.WaitGroup //表单提交完毕的等待计数
	removeLis                  sync.WaitGroup //移除事件监听
	domWG                      sync.WaitGroup //DOMContentLoaded 的等待计数
	fillFormWG                 sync.WaitGroup //填充表单任务
}

func NewCrawler(config Config, urlChecker *checker.URLChecker) *Crawler {
	crawler := &Crawler{
		config:     &config,
		taskQueue:  collections.NewQueue(),
		taskChan:   make(chan *task, 100),
		urlChecker: urlChecker,
		smartFilter: SmartFilter{
			SimpleFilter: SimpleFilter{},
		},
	}

	crawler.smartFilter.Init()
	crawler.config.TaskConfig = &TaskConfig{
		MaxCrawlCount:           config.MaxCountOfURLs,
		MaxTabsCount:            config.MaxConcurrent,
		MaxDepth:                config.MaxDepth,
		IncognitoContext:        false,
		TabRunTimeout:           TabRunTimeout,
		DomContentLoadedTimeout: DomContentLoadedTimeout,
		EventTriggerInterval:    EventTriggerInterval,
		BeforeExitDelay:         BeforeExitDelay,
		EventTriggerMode:        DefaultEventTriggerMode,
		IgnoreKeywords:          DefaultIgnoreKeywords,
		CustomFormValues:        make(map[string]string),
		ExtraHeaders:            make(map[string]any),
	}

	// Apply timeout configs from BrowserConfig
	if config.NavigateTimeoutSecond > 0 {
		crawler.config.TaskConfig.TabRunTimeout = time.Duration(config.NavigateTimeoutSecond) * time.Second
	}
	if config.LoadTimeoutSecond > 0 {
		crawler.config.TaskConfig.DomContentLoadedTimeout = time.Duration(config.LoadTimeoutSecond) * time.Second
	}
	if config.PageAnalyzeTimeoutSecond > 0 {
		// Used for page analysis timeout
	}

	crawler.ctx, crawler.cancel = context.WithCancel(context.Background())
	crawler.crawledCount = make(map[string]int)
	if config.HTTPClientOptions != nil {
		crawler.Client = http.NewClientWithOptions(config.HTTPClientOptions)
	} else if config.Proxy != "" {
		opts := &http.ClientOptions{Proxy: config.Proxy, TLSSkipVerify: true}
		crawler.Client = http.NewClientWithOptions(opts)
	} else {
		crawler.Client = http.NewClient()
	}
	if config.Browser {
		windowWidth := config.WindowWidth
		if windowWidth <= 0 {
			windowWidth = 1920
		}
		windowHeight := config.WindowHeight
		if windowHeight <= 0 {
			windowHeight = 1080
		}
		crawler.InitBrowser(config.ExecPath, crawler.config.TaskConfig.IncognitoContext, crawler.config.TaskConfig.ExtraHeaders, config.Proxy, config.DisableHeadless, config.ForceSandbox, windowWidth, windowHeight)
	}
	crawler.config.TaskConfig.CustomFormValues["default"] = DefaultInputText
	// 创建协程池
	p, _ := ants.NewPool(crawler.config.MaxConcurrent)
	crawler.Pool = p
	crawler.Browser = crawler.bro

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
	for !c.feedEnded {
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

func (*Crawler) Login(ctx context.Context) error {
	return nil
}

func (c *Crawler) NewTask(req *http.Request, depth int) {
	if req == nil {
		logger.Println("Invalid request.")
		return
	}
	if c.config.MaxDepth > 0 && depth > c.config.MaxDepth {
		logger.Infof("Dropping request %s: depth %d exceeds max depth %d", req.GetURL().String(), depth, c.config.MaxDepth)
		return
	}
	// 通过检查器检查URL是否合法
	if !c.urlChecker.TargetStr(req.GetURL().String()).IsAllowed().Bool() {
		logger.Debugf("URL is not Allowed: %s", req.GetURL().String())
		return
	}
	if c.smartFilter.DoFilter(req, false) {
		logger.Debugf("smartFilter req: " + req.GetURL().String())
		return
	}

	c.crawledCountLock.Lock()
	key := fmt.Sprintf("%s://%s", req.GetURL().Scheme, req.GetURL().Host)
	c.crawledCount[key] += 1
	if c.config.MaxCountOfURLs != 0 && c.crawledCount[key] > c.config.MaxCountOfURLs {
		logger.Infof("Dropping request : crawled count %d exceeds max allowed URLs %d", c.crawledCount[key], c.config.MaxCountOfURLs)
		c.crawledCountLock.Unlock()
		return
	}
	// Per-site visit limit
	if c.config.MaxPageVisitPerSite > 0 && c.crawledCount[key] > c.config.MaxPageVisitPerSite {
		logger.Debugf("Dropping request: per-site count %d exceeds max %d for %s", c.crawledCount[key], c.config.MaxPageVisitPerSite, key)
		c.crawledCountLock.Unlock()
		return
	}
	c.crawledCountLock.Unlock()

	// 新建一个任务
	t := &task{
		req:           req,
		redirectCount: 0,
		depth:         depth,
		crawlerTask:   c,
		browser:       c.Browser,
	}
	c.wg.Add(1)
	// 将任务添加到任务队列中
	c.taskQueue.PushBack(t)

	logger.Infof("New task added: %s %s", t.req.Method, t.req.GetURL().String())
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

// func (*Crawler) OnResponse()
func (c *Crawler) OnFlow(handler func(flow *http.Flow) bool) {
	c.flowHandlersMutex.Lock()
	defer c.flowHandlersMutex.Unlock()
	c.flowHandlers = append(c.flowHandlers, handler)
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
		if !handler(r) {
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

func (c *Crawler) handleFlow(flow *http.Flow) bool {
	c.responseHandlersMutex.Lock()
	defer c.responseHandlersMutex.Unlock()
	for _, handler := range c.flowHandlers {
		if !handler(flow) {
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
	logger.Infof("Crawler End")
	c.clear()
}

func (c *Crawler) clear() {
	if c.Browser != nil {
		c.Browser.Close()
	}
	if c.Pool != nil {
		c.Pool.Release() // 释放协程池
	}

}

func (c *Crawler) handleTask(t *task) {
	if c.config.Browser {
		c.handleBrowserTask(t)
	} else {
		c.handleBasicTask(t)
	}
}

func (c *Crawler) newWorker(id int) {
	for {
		select {
		case <-c.ctx.Done():
			return
		case t := <-c.taskChan:
			c.handleTask(t)
			c.wg.Done()

		}
	}
}
