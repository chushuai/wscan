/*
*
2 * @Author: shaochuyu
3 * @Date: 12/9/22
4
*/
package crawler

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	gohttp "net/http"
	"net/textproto"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
	"wscan/core/crawler/js"
	"wscan/core/http"
	"wscan/core/utils"
	logger "wscan/core/utils/log"

	"github.com/PuerkitoBio/goquery"
	"github.com/chromedp/cdproto/browser"
	"github.com/chromedp/cdproto/cdp"
	"github.com/chromedp/cdproto/dom"
	"github.com/chromedp/cdproto/fetch"
	"github.com/chromedp/cdproto/network"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/cdproto/runtime"
	"github.com/chromedp/chromedp"
	"github.com/panjf2000/ants/v2"
)

type Browser struct {
	Ctx        *context.Context
	Cancel     *context.CancelFunc
	tabs       []*context.Context
	tabCancels []context.CancelFunc
	// ExtraHeaders map[string]any
	lock sync.Mutex
}

func (c *Crawler) InitBrowser(chromiumPath string, incognito bool, extraHeaders map[string]any, proxy string, noHeadless bool, forceSandbox bool, windowWidth int, windowHeight int) {
	var bro Browser
	if windowWidth <= 0 {
		windowWidth = 1920
	}
	if windowHeight <= 0 {
		windowHeight = 1080
	}
	opts := append(chromedp.DefaultExecAllocatorOptions[:],

		// 执行路径
		chromedp.ExecPath(chromiumPath),
		// 无头模式
		chromedp.Flag("headless", !noHeadless),
		// 禁用GPU，不显示GUI
		chromedp.Flag("disable-gpu", true),
		// 隐身模式启动
		chromedp.Flag("incognito", incognito),
		// 取消沙盒模式
		chromedp.Flag("no-sandbox", !forceSandbox),
		// 忽略证书错误
		chromedp.Flag("ignore-certificate-errors", true),

		//chromedp.Flag("disable-images", true),
		//
		chromedp.Flag("disable-web-security", true),
		//
		chromedp.Flag("disable-xss-auditor", true),
		//
		chromedp.Flag("disable-setuid-sandbox", true),

		chromedp.Flag("allow-running-insecure-content", true),

		//chromedp.Flag("disable-webgl", true),

		chromedp.Flag("disable-popup-blocking", true),
		// no-default-browser-check
		chromedp.WindowSize(windowWidth, windowHeight),
	)
	// 设置浏览器代理
	if proxy != "" {
		opts = append(opts, chromedp.ProxyServer(proxy))
	}

	allocCtx, cancel := chromedp.NewExecAllocator(context.Background(), opts...)
	bctx, _ := chromedp.NewContext(allocCtx,
		chromedp.WithLogf(log.Printf),
	)
	// https://github.com/chromedp/chromedp/issues/824#issuecomment-845664441
	// 如果需要在一个浏览器上创建多个tab，则需要先创建浏览器的上下文，即运行下面的语句
	if err := chromedp.Run(bctx); err != nil {
		logger.Fatal(err)
	}
	bro.Cancel = &cancel
	bro.Ctx = &bctx
	// bro.ExtraHeaders = extraHeaders
	c.bro = &bro

}

func (bro *Browser) NewTab(timeout time.Duration) (*context.Context, context.CancelFunc) {
	bro.lock.Lock()
	ctx, cancel := chromedp.NewContext(*bro.Ctx)
	tCtx, _ := context.WithTimeout(ctx, timeout)
	bro.tabs = append(bro.tabs, &tCtx)
	bro.tabCancels = append(bro.tabCancels, cancel)

	bro.lock.Unlock()

	return &tCtx, cancel
}

func (bro *Browser) Close() {
	logger.Info("closing browser.")
	if bro.Ctx == nil {
		return
	}
	for _, cancel := range bro.tabCancels {
		cancel()
	}

	for _, ctx := range bro.tabs {
		err := browser.Close().Do(*ctx)
		if err != nil {
			logger.Debug(err)
		}
	}

	err := browser.Close().Do(*bro.Ctx)
	if err != nil {
		logger.Debug(err)
	}
	(*bro.Cancel)()
}

type TabConfig struct {
	TabRunTimeout           time.Duration
	DomContentLoadedTimeout time.Duration
	EventTriggerMode        string        // 事件触发的调用方式： 异步 或 顺序
	EventTriggerInterval    time.Duration // 事件触发的间隔 单位毫秒
	BeforeExitDelay         time.Duration // 退出前的等待时间，等待DOM渲染，等待XHR发出捕获
	EncodeURLWithCharset    bool
	IgnoreKeywords          []string //
	Proxy                   string
	CustomFormValues        map[string]string
	CustomFormKeywordValues map[string]string
}

type bindingCallPayload struct {
	Name string   `json:"name"`
	Seq  int      `json:"seq"`
	Args []string `json:"args"`
}

func waitNavigateDone(ctx context.Context) error {
	ch := make(chan struct{})
	lCtx, lCancel := context.WithCancel(ctx)
	tCtx, cancel := context.WithTimeout(ctx, DomContentLoadedTimeout)
	defer cancel()
	chromedp.ListenTarget(lCtx, func(ev any) {
		if _, ok := ev.(*page.EventDomContentEventFired); ok {
			lCancel()
			close(ch)
		} else if _, ok := ev.(*page.EventLoadEventFired); ok {
			lCancel()
			close(ch)
		}
	})
	select {
	case <-ch:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	case <-tCtx.Done():
		return tCtx.Err()
	}
}

func (tab *task) Start() {
	logger.Infof("Start Crawling  %s %s", tab.NavigateReq.Method, tab.NavigateReq.GetURL().String())
	defer tab.Cancel()
	if err := chromedp.Run(*tab.Ctx,
		RunWithTimeOut(tab.Ctx, tab.config.DomContentLoadedTimeout, chromedp.Tasks{
			// 开启网络层API
			network.Enable(),
			// 开启请求拦截API
			fetch.Enable().WithHandleAuthRequests(true),
			// 添加回调函数绑定
			// XSS-Scan 使用的回调
			runtime.AddBinding("addLink"),
			runtime.AddBinding("Test"),
			// 初始化执行JS
			chromedp.ActionFunc(func(ctx context.Context) error {
				var err error
				_, err = page.AddScriptToEvaluateOnNewDocument(js.TabInitJS).Do(ctx)
				if err != nil {
					logger.Error("TabInitJS", err.Error())
					return err
				}
				return nil
			}),
			network.SetExtraHTTPHeaders(tab.ExtraHeaders),
			// 通过 CDP 的 SetCookie API 注入配置中的 Cookie（不能通过 SetExtraHTTPHeaders，会与 Chrome 自身 Cookie 管理冲突导致事件解析报错）
			chromedp.ActionFunc(func(ctx context.Context) error {
				for _, cookieStr := range tab.NavigateReq.Header["Cookie"] {
					for _, part := range strings.Split(cookieStr, ";") {
						part = strings.TrimSpace(part)
						if idx := strings.Index(part, "="); idx > 0 {
							name := part[:idx]
							value := part[idx+1:]
							err := network.SetCookie(name, value).
								WithDomain(tab.NavigateReq.GetURL().Hostname()).
								WithPath("/").
								Do(ctx)
							if err != nil {
								logger.Debugf("SetCookie %s failed: %v", name, err)
							}
						}
					}
				}
				return nil
			}),
			// 执行导航
			//chromedp.Navigate(tab.NavigateReq.URL.String()),
			chromedp.ActionFunc(func(ctx context.Context) error {
				logger.Infof("Navigate URL: %s", tab.NavigateReq.GetURL().String())
				_, _, errTxt, err := page.Navigate(tab.NavigateReq.GetURL().String()).Do(ctx)
				if errTxt != "" { // ERR_CONNECTION_TIMED_OUT   ERR_NAME_NOT_RESOLVED
					logger.Error("Navigate Url Error: ", errTxt, " ", tab.NavigateReq.GetURL().String(), tab.NavigateReq)
					return errors.New(errTxt)
				}
				if err != nil {
					logger.Error("Navigate Url Error:", err.Error(), " ", tab.NavigateReq.GetURL().String(), tab.NavigateReq)
					return err
				}
				return waitNavigateDone(ctx)
			}),
		}),
	); err != nil {
		if err.Error() == "context canceled" {
			return
		}
		logger.Warn("navigate timeout: ", " ", err.Error(), " ", tab.NavigateReq.GetURL().String())
	}

	go func() {
		// 等待所有协程任务结束
		tab.WG.Wait()
		tab.NavDone <- 1
	}()

	select {
	case <-tab.NavDone:
	case <-time.After(tab.config.DomContentLoadedTimeout + time.Second*15):
		logger.Warn("navigation tasks TIMEOUT.")
	}

	// 等待收集所有链接
	tab.collectLinkWG.Add(3)
	go tab.collectLinks()
	tab.collectLinkWG.Wait()

	// 识别页面编码 并编码所有URL
	if tab.config.EncodeURLWithCharset {
		tab.DetectCharset()
		//tab.EncodeAllURLWithCharset()
	}
}

func RunWithTimeOut(ctx *context.Context, timeout time.Duration, tasks chromedp.Tasks) chromedp.ActionFunc {
	return func(ctx context.Context) error {
		timeoutContext, _ := context.WithTimeout(ctx, timeout)
		//defer cancel()
		return tasks.Do(timeoutContext)
	}
}

/*
*
添加收集到的URL到结果列表，需要处理Host绑定
*/
func (tt *task) AddResultUrl(method string, _url string, source string) {
	// #
	if strings.HasPrefix(_url, "data:") || strings.HasPrefix(_url, "javascript:") ||
		strings.HasPrefix(_url, "chrome-error:") || strings.HasPrefix(_url, "chrome://") ||
		strings.HasPrefix(_url, "#") || strings.HasPrefix(_url, "mailto:") {
		return
	}

	navUrl := tt.NavigateReq.GetURL()
	url, err := http.GetUrl(_url, *navUrl)
	if err != nil {
		return
	}
	logger.Infof("Found url %s method %s source %s", url.String(), method, source)
	referer := navUrl.String()
	// 处理Host绑定
	host := tt.NavigateReq.Header.Get("Host")
	if host != navUrl.Hostname() && url.Hostname() == host {
		url, _ = http.GetUrl(strings.Replace(url.String(), "://"+url.Hostname(), "://"+navUrl.Hostname(), -1), *navUrl)
		referer = strings.Replace(navUrl.String(), navUrl.Host, host, -1)
	}

	if url == nil {
		return
	}

	req, _ := http.NewRequest(method, url.String(), nil)

	for key, value := range tt.ExtraHeaders {
		if value.(string) == "" {
			continue
		}
		req.Header.Set(key, value.(string))
	}
	req.Header.Set("Referer", referer)
	if len(tt.NavigateReq.Header["Cookie"]) > 0 {
		req.Header["Cookie"] = tt.NavigateReq.Header["Cookie"]
	}
	if host != "" {
		req.Header.Set("Host", host)
	}

	tt.crawlerTask.NewTask(req, tt.depth+1)
}

/*
*
添加请求到结果列表，拦截请求时处理了Host绑定，此处无需处理
*/
func (tt *task) AddResultRequest(req *http.Request) {
	for key, value := range tt.ExtraHeaders {
		req.Header[key] = []string{value.(string)}
	}
	tt.crawlerTask.NewTask(req, tt.depth+1)
}

/*
*
获取当前标签页CDP的执行上下文
*/
func (tt *task) GetExecutor() context.Context {
	c := chromedp.FromContext(*tt.Ctx)
	ctx := cdp.WithExecutor(*tt.Ctx, c.Target)
	return ctx
}

/*
*
关闭弹窗
*/
func (tt *task) dismissDialog() {
	defer tt.WG.Done()
	ctx := tt.GetExecutor()
	_ = page.HandleJavaScriptDialog(false).Do(ctx)
}

/*
*
处理回调
*/
func (tt *task) HandleBindingCalled(event *runtime.EventBindingCalled) {
	defer tt.WG.Done()
	payload := []byte(event.Payload)
	var bcPayload bindingCallPayload
	_ = json.Unmarshal(payload, &bcPayload)
	if bcPayload.Name == "addLink" && len(bcPayload.Args) > 1 {
		tt.AddResultUrl(GET, bcPayload.Args[0], bcPayload.Args[1])
	}
	if bcPayload.Name == "Test" {
		fmt.Println(bcPayload.Args)
	}
	tt.Evaluate(fmt.Sprintf(js.DeliverResultJS, bcPayload.Name, bcPayload.Seq, "s"))
}

/*
*

执行JS
*/
func (tab *task) Evaluate(expression string) {
	ctx := tab.GetExecutor()
	tCtx, cancel := context.WithTimeout(ctx, time.Second*5)
	defer cancel()
	_, exception, err := runtime.Evaluate(expression).Do(tCtx)
	if exception != nil {
		logger.Debug("tab Evaluate: ", exception.Text, expression)
	}
	if err != nil {
		logger.Debug("tab Evaluate: ", err)
	}
}

/*
*
立即根据条件获取Nodes的ID，不等待
*/
func (tt *task) GetNodeIDs(sel string) ([]cdp.NodeID, error) {
	ctx := tt.GetExecutor()
	return dom.QuerySelectorAll(tt.DocBodyNodeId, sel).Do(ctx)
}

/*
*
根据给的Node执行JS
*/
func (tab *task) EvaluateWithNode(expression string, node *cdp.Node) error {
	ctx := tab.GetExecutor()
	var res bool
	err := chromedp.EvaluateAsDevTools(js.Snippet(expression, js.CashX(true), "", node), &res).Do(ctx)
	if err != nil {
		return err
	}
	return nil
}

/*
*
识别页面的编码
*/
func (tab *task) DetectCharset() {
	ctx := tab.GetExecutor()
	tCtx, cancel := context.WithTimeout(ctx, time.Millisecond*500)
	defer cancel()
	var content string
	var ok bool
	var getCharsetRegex = regexp.MustCompile("charset=(.+)$")
	err := chromedp.AttributeValue(`meta[http-equiv=Content-Type]`, "content", &content, &ok, chromedp.ByQuery).Do(tCtx)
	if err != nil || ok != true {
		return
	}
	if strings.Contains(content, "charset=") {
		charset := getCharsetRegex.FindString(content)
		if charset != "" {
			tab.PageCharset = strings.ToUpper(strings.Replace(charset, "charset=", "", -1))
			tab.PageCharset = strings.TrimSpace(tab.PageCharset)
		}
	}
}

//

/*
*
在页面Loaded之后执行
同时等待 afterDOMRun 之后执行
*/
func (tab *task) AfterLoadedRun() {
	defer tab.WG.Done()
	tab.formSubmitWG.Add(2)
	tab.loadedWG.Add(3)
	tab.removeLis.Add(1)

	go tab.formSubmit()
	tab.formSubmitWG.Wait()

	if tab.config.EventTriggerMode == EventTriggerAsync {
		go tab.triggerJavascriptProtocol()
		go tab.triggerInlineEvents()
		go tab.triggerDom2Events()
		tab.loadedWG.Wait()
	} else if tab.config.EventTriggerMode == EventTriggerSync {
		tab.triggerInlineEvents()
		time.Sleep(tab.config.EventTriggerInterval)
		tab.triggerDom2Events()
		time.Sleep(tab.config.EventTriggerInterval)
		tab.triggerJavascriptProtocol()
	}

	// 事件触发之后 需要等待一点时间让浏览器成功发出ajax请求 更新DOM
	time.Sleep(tab.config.BeforeExitDelay)

	go tab.RemoveDOMListener()
	tab.removeLis.Wait()
}

/*
*
自动化点击提交表单
*/
func (tab *task) formSubmit() {
	// 首先对form表单设置target
	tab.setFormToFrame()

	// 接下来尝试三种方式提交表单
	go tab.clickSubmit()
	go tab.clickAllButton()
}

/*
*
设置form的target指向一个frame
*/
func (tab *task) setFormToFrame() {
	// 首先新建 frame
	nameStr := utils.RandLower(8)
	tab.Evaluate(fmt.Sprintf(js.NewFrameTemplate, nameStr, nameStr))

	// 接下来将所有的 form 节点target都指向它
	ctx := tab.GetExecutor()
	formNodes, formErr := tab.GetNodeIDs(`form`)
	if formErr != nil {
		logger.Errorf("setFormToFrame: %v", formErr)
		return
	}
	if len(formNodes) == 0 {
		return
	}
	tCtx, cancel := context.WithTimeout(ctx, time.Second*2)
	defer cancel()
	_ = chromedp.SetAttributeValue(formNodes, "target", nameStr, chromedp.ByNodeID).Do(tCtx)
}

/*
*
点击按钮 type=submit
*/
func (tab *task) clickSubmit() {
	defer tab.formSubmitWG.Done()

	// 首先点击按钮 type=submit
	ctx := tab.GetExecutor()

	// 获取所有的form节点 直接执行submit
	formNodes, formErr := tab.GetNodeIDs(`form`)
	if formErr != nil {
		logger.Errorf("clickSubmit: %v", formErr)
		return
	}
	if len(formNodes) == 0 {
		return
	}
	tCtx1, cancel1 := context.WithTimeout(ctx, time.Second*2)
	defer cancel1()
	_ = chromedp.Submit(formNodes, chromedp.ByNodeID).Do(tCtx1)

	// 获取所有的input标签
	inputNodes, inputErr := tab.GetNodeIDs(`form input[type=submit]`)
	if inputErr != nil || len(inputNodes) == 0 {
		logger.Debug("clickSubmit: get form input element err")
		if inputErr != nil {
			logger.Debug(inputErr)
		}
		return
	}
	tCtx2, cancel2 := context.WithTimeout(ctx, time.Second*2)
	defer cancel2()
	_ = chromedp.Click(inputNodes, chromedp.ByNodeID).Do(tCtx2)
}

/*
*
click all button
*/
func (tab *task) clickAllButton() {
	defer tab.formSubmitWG.Done()
	// 获取所有的form中的button节点
	ctx := tab.GetExecutor()
	// 获取所有的button标签
	btnNodeIDs, bErr := tab.GetNodeIDs(`form button`)
	if bErr != nil {
		logger.Errorf("clickAllButton: %v", bErr)
		return
	}
	if len(btnNodeIDs) == 0 {
		return
	}
	tCtx, cancel1 := context.WithTimeout(ctx, time.Second*2)
	defer cancel1()
	_ = chromedp.Click(btnNodeIDs, chromedp.ByNodeID).Do(tCtx)

	// 使用JS的click方法进行点击
	var btnNodes []*cdp.Node
	tCtx2, cancel2 := context.WithTimeout(ctx, time.Second*2)
	defer cancel2()
	err := chromedp.Nodes(btnNodeIDs, &btnNodes, chromedp.ByNodeID).Do(tCtx2)
	if err != nil {
		return
	}
	for _, node := range btnNodes {
		logger.Info(node)
		_ = tab.EvaluateWithNode(js.FormNodeClickJS, node)
	}
}

/*
*
触发内联事件
*/
func (tab *task) triggerInlineEvents() {
	defer tab.loadedWG.Done()
	tab.Evaluate(fmt.Sprintf(js.TriggerInlineEventJS, tab.config.EventTriggerInterval.Seconds()*1000))

}

/*
*
触发DOM2级事件
*/
func (tab *task) triggerDom2Events() {
	defer tab.loadedWG.Done()
	tab.Evaluate(fmt.Sprintf(js.TriggerDom2EventJS, tab.config.EventTriggerInterval.Seconds()*1000))
}

/*
*
a标签的href值为伪协议，
*/
func (tab *task) triggerJavascriptProtocol() {
	defer tab.loadedWG.Done()
	tab.Evaluate(fmt.Sprintf(js.TriggerJavascriptProtocol, tab.config.EventTriggerInterval.Seconds()*1000,
		tab.config.EventTriggerInterval.Seconds()*1000))
}

/*
*
移除DOM节点变化监听
*/
func (tab *task) RemoveDOMListener() {
	defer tab.removeLis.Done()
	// 移除DOM节点变化监听
	tab.Evaluate(js.RemoveDOMListenerJS)
}

/*
*
在DOMContentLoaded完成后执行
*/
func (tab *task) AfterDOMRun() {
	defer tab.WG.Done()

	// 获取当前body节点的nodeId 用于之后查找子节点
	if !tab.getBodyNodeId() {
		logger.Debug("no body document NodeID, exit.")
		return
	}

	tab.domWG.Add(2)
	go tab.fillForm()
	go tab.setObserverJS()
	tab.domWG.Wait()
	tab.WG.Add(1)
	go tab.AfterLoadedRun()
}

/*
*
获取的Body的NodeId 用于之后子节点无等待查询
最多等待3秒 如果DOM依旧没有渲染完成，则退出
*/
func (tab *task) getBodyNodeId() bool {
	var docNodeIDs []cdp.NodeID
	ctx := tab.GetExecutor()
	tCtx, cancel := context.WithTimeout(ctx, time.Second*3)
	defer cancel()
	// 获取 Frame document root
	err := chromedp.NodeIDs(`body`, &docNodeIDs, chromedp.ByQuery).Do(tCtx)
	if len(docNodeIDs) == 0 || err != nil {
		// not root node yet?
		logger.Debug("getBodyNodeId failed, maybe DOM not ready?")
		if err != nil {
			logger.Debug(err)
		}
		return false
	}
	tab.DocBodyNodeId = docNodeIDs[0]
	return true
}

/*
*
自动化填充表单
*/
func (tt *task) fillForm() {
	defer tt.domWG.Done()
	tt.fillFormWG.Add(3)
	f := FillForm{
		tab: tt,
	}

	go f.fillInput()
	go f.fillMultiSelect()
	go f.fillTextarea()

	tt.fillFormWG.Wait()
}

/*
*
设置Dom节点变化的观察函数
*/
func (tab *task) setObserverJS() {
	defer tab.domWG.Done()
	// 设置Dom节点变化的观察函数
	go tab.Evaluate(js.ObserverJS)
}

func IsIgnoredByKeywordMatch(req *http.Request, IgnoreKeywords []string) bool {
	for _, _str := range IgnoreKeywords {
		if strings.Contains(req.GetURL().String(), _str) {
			logger.Info("ignore request: %s ", string(req.Dump()))
			return true
		}
	}
	return false
}

/*
*
处理每一个HTTP请求
*/
func (tab *task) InterceptRequest(v *fetch.EventRequestPaused) {
	defer tab.WG.Done()
	ctx := tab.GetExecutor()
	_req := v.Request
	// 拦截到的URL格式一定正常 不处理错误
	url, err := http.GetUrl(_req.URL, *tab.NavigateReq.GetURL())
	if err != nil {
		logger.Errorf("InterceptRequest parse url failed: %s", err.Error())
		_ = fetch.ContinueRequest(v.RequestID).Do(ctx)
		return
	}
	postData := ""
	if _req.HasPostData && len(_req.PostDataEntries) > 0 {
		postData = _req.PostDataEntries[0].Bytes
	}
	req, _ := http.NewRequest(_req.Method, url.String(), strings.NewReader(postData))

	for kk, vv := range _req.Headers {
		if vv.(string) == "" {
			continue
		}
		req.Header.Set(kk, vv.(string))
	}
	if IsIgnoredByKeywordMatch(req, tab.config.IgnoreKeywords) {
		_ = fetch.FailRequest(v.RequestID, network.ErrorReasonBlockedByClient).Do(ctx)
		// req.Source = FromXHR
		tab.AddResultRequest(req)
		return
	}
	tab.HandleHostBinding(req)
	// 静态资源 全部阻断
	for _, suffix := range StaticSuffix {
		if strings.HasSuffix(strings.ToLower(url.Path), suffix) && url.Path != "/robots.txt" {
			_ = fetch.FailRequest(v.RequestID, network.ErrorReasonBlockedByClient).Do(ctx)
			// req.Source = FromStaticRes
			tab.AddResultRequest(req)
			return
		}
	}
	// 处理导航请求
	if tab.IsNavigatorRequest(v.NetworkID.String()) {
		tab.NavNetworkID = v.NetworkID.String()
		tab.HandleNavigationReq(req, v)
		// req.Source = FromNavigation
		tab.AddResultRequest(req)
		return
	}
	// req.Source = FromXHR
	tab.AddResultRequest(req)
	err = fetch.ContinueRequest(v.RequestID).Do(ctx)
	if err != nil {
		logger.Error(err.Error())
	}
}

/*
*
判断是否为导航请求
*/
func (tab *task) IsNavigatorRequest(networkID string) bool {
	return networkID == tab.LoaderID
}

/*
*
处理 401 407 认证弹窗
*/
func (tab *task) HandleAuthRequired(req *fetch.EventAuthRequired) {
	defer tab.WG.Done()
	logger.Debug("auth required found, auto auth.")
	ctx := tab.GetExecutor()
	authRes := fetch.AuthChallengeResponse{
		Response: fetch.AuthChallengeResponseResponseProvideCredentials,
		Username: "Scan",
		Password: "Scan",
	}
	// 取消认证
	_ = fetch.ContinueWithAuth(req.RequestID, &authRes).Do(ctx)
}

/*
*
处理导航请求
*/
func (tab *task) HandleNavigationReq(req *http.Request, v *fetch.EventRequestPaused) {
	navReq := tab.NavigateReq
	ctx := tab.GetExecutor()
	tCtx, cancel := context.WithTimeout(ctx, time.Second*5)
	defer cancel()
	logger.Infof("%s, %s", v.RequestID, req.URL)
	overrideReq := fetch.ContinueRequest(v.RequestID).WithURL(req.GetURL().String())
	// 处理后端重定向请求
	if tab.FoundRedirection && tab.IsTopFrame(v.FrameID.String()) {
		logger.Debug("redirect navigation req: " + req.GetURL().String())
		//_ = fetch.FailRequest(v.RequestID, network.ErrorReasonConnectionAborted).Do(ctx)
		body := base64.StdEncoding.EncodeToString([]byte(`<html><body>Scanner</body></html>`))
		param := fetch.FulfillRequest(v.RequestID, 200).WithBody(body)
		err := param.Do(ctx)
		if err != nil {
			logger.Error(err)
		}
		tab.NavigateReqRedirectionFlag = true
		// navReq.Source = FromNavigation
		tab.AddResultRequest(&navReq)
		// 处理重定向标记
	} else if tab.NavigateReqRedirectionFlag && tab.IsTopFrame(v.FrameID.String()) {
		tab.NavigateReqRedirectionFlag = false
		postData := req.GetRawBody()
		newReq, _ := http.NewRequest(req.Method, req.GetURL().String(), bytes.NewReader(postData))
		res, err := tab.crawlerTask.Client.DoRaw(newReq)
		if err != nil {
			logger.Error(err.Error(), req.GetURL().String())
			// 处理错误
			tab.crawlerTask.handleErr(err)
			return
		}

		if err != nil {
			logger.Error(err)
			_ = fetch.FailRequest(v.RequestID, network.ErrorReasonConnectionAborted).Do(ctx)
			return
		}
		text := req.GetRawBody()
		body := base64.StdEncoding.EncodeToString(text)
		param := fetch.FulfillRequest(v.RequestID, 200).WithResponseHeaders(ConvertHeadersNoLocation(res.Header)).WithBody(body)
		errR := param.Do(ctx)
		if errR != nil {
			logger.Debug(errR)
		}
		// 主导航请求
	} else if tab.IsTopFrame(v.FrameID.String()) && NavigationUrl(req.GetURL().RawUrl()) == NavigationUrl(navReq.GetURL().RawUrl()) {
		logger.Debug("main navigation req: " + navReq.GetURL().String())
		// 手动设置POST信息
		if navReq.Method == POST || navReq.Method == PUT {
			postData := req.GetRawBody()
			overrideReq = overrideReq.WithPostData(string(postData))
		}
		overrideReq = overrideReq.WithMethod(navReq.Method)
		overrideReq = overrideReq.WithHeaders(MergeHeaders(navReq.Header, req.Header))
		err := overrideReq.Do(tCtx)
		if err != nil {
			logger.Error(err.Error())
		}

		// 子frame的导航
	} else if !tab.IsTopFrame(v.FrameID.String()) {
		err := overrideReq.Do(tCtx)
		if err != nil {
			logger.Error(err.Error())
		}
		// 前端跳转 返回204
	} else {
		logger.Infof("FulfillRequest: ", v.RequestID.String())
		err := fetch.FulfillRequest(v.RequestID, 204).Do(ctx)
		if err != nil {
			logger.Error(err.Error())
		}
	}
}

/*
*
处理Host绑定
*/
func (tab *task) HandleHostBinding(req *http.Request) {
	url := req.GetURL()
	navUrl := tab.NavigateReq.GetURL()
	// 导航请求的域名和HOST绑定中的域名不同，且当前请求的domain和导航请求header中的Host相同，则替换当前请求的domain并绑定Host
	if host := tab.NavigateReq.Header.Get("Host"); host != "" {
		if navUrl.Hostname() != host && url.Host == host {
			urlObj, _ := http.GetUrl(strings.Replace(req.GetURL().String(), "://"+url.Hostname(), "://"+navUrl.Hostname(), -1), *navUrl)
			req.SetURL(urlObj.RawUrl())
			req.Header.Set("Host", host)

		} else if navUrl.Hostname() != host && url.Host == navUrl.Host {
			req.Header.Set("Host", host)
		}
		// 修正Origin
		if _, ok := req.Header["Origin"]; ok {
			req.Header.Set("Origin", strings.Replace(req.Header.Get("Origin"), navUrl.Host, host, 1))
		}
		// 修正Referer
		if _, ok := req.Header["Referer"]; ok {
			req.Header.Set("Referer", strings.Replace(req.Header.Get("Referer"), navUrl.Host, host, 1))
		} else {
			req.Header.Set("Referer", strings.Replace(navUrl.String(), navUrl.Host, host, 1))
		}
	}
}

func (tab *task) IsTopFrame(FrameID string) bool {
	return FrameID == tab.TopFrameId
}

/*
*
解析响应内容中的URL 使用正则匹配
*/
func (tab *task) ParseResponseURL(v *network.EventResponseReceived) {
	defer tab.WG.Done()
	ctx := tab.GetExecutor()
	res, err := network.GetResponseBody(v.RequestID).Do(ctx)
	if err != nil {
		logger.Warnf("ParseResponseURL %s", err.Error())
		return
	}
	resStr := string(res)
	navUrl := tab.NavigateReq.GetURL()
	for _, r := range ParseResponseURL(navUrl.RawUrl(), resStr) {
		tab.AddResultUrl(GET, r.GetURL().String(), FromJSFile)
	}
}

func (tab *task) HandleRedirectionResp(v *network.EventResponseReceivedExtraInfo) {
	defer tab.WG.Done()
	statusCode := tab.GetStatusCode(v.HeadersText)
	// 导航请求，且返回重定向
	if 300 <= statusCode && statusCode < 400 {
		logger.Debug("set redirect flag.")
		tab.FoundRedirection = true
	}
}

func (tab *task) GetContentCharset(v *network.EventResponseReceived) {
	defer tab.WG.Done()
	var getCharsetRegex = regexp.MustCompile("charset=(.+)$")
	for key, value := range v.Response.Headers {
		if key == "Content-Type" {
			value := value.(string)
			if strings.Contains(value, "charset") {
				value = getCharsetRegex.FindString(value)
				value = strings.ToUpper(strings.Replace(value, "charset=", "", -1))
				tab.PageCharset = value
				tab.PageCharset = strings.TrimSpace(tab.PageCharset)
			}
		}
	}
}

func (tab *task) GetStatusCode(headerText string) int {
	rspInput := strings.NewReader(headerText)
	rspBuf := bufio.NewReader(rspInput)
	tp := textproto.NewReader(rspBuf)
	line, err := tp.ReadLine()
	if err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return 0
	}
	parts := strings.Split(line, " ")
	if len(parts) < 3 {
		return 0
	}
	code, _ := strconv.Atoi(parts[1])
	return code
}

func MergeHeaders(navHeaders gohttp.Header, headers gohttp.Header) []*fetch.HeaderEntry {
	var mergedHeaders []*fetch.HeaderEntry
	for key, value := range navHeaders {
		if _, ok := headers[key]; !ok {
			var header fetch.HeaderEntry
			header.Name = key
			if len(value) == 0 || value[0] == "" {
				continue
			} else {
				header.Value = value[0]
			}
			mergedHeaders = append(mergedHeaders, &header)
		}
	}

	for key, value := range headers {
		var header fetch.HeaderEntry
		header.Name = key
		header.Value = value[0]
		if header.Value == "" {
			continue
		}
		mergedHeaders = append(mergedHeaders, &header)
	}
	return mergedHeaders
}

func ConvertHeadersNoLocation(h map[string][]string) []*fetch.HeaderEntry {
	var headers []*fetch.HeaderEntry
	for key, value := range h {
		if key == "Location" {
			continue
		}
		var header fetch.HeaderEntry
		header.Name = key
		header.Value = value[0]
		headers = append(headers, &header)
	}
	return headers
}

/*
*
最后收集所有的链接
*/
func (tab *task) collectLinks() {
	go tab.collectHrefLinks()
	go tab.collectObjectLinks()
	go tab.collectCommentLinks()
}

func (tab *task) collectHrefLinks() {
	defer tab.collectLinkWG.Done()
	ctx := tab.GetExecutor()
	// 收集 src href data-url 属性值
	attrNameList := []string{"src", "href", "data-url", "data-href"}
	for _, attrName := range attrNameList {
		tCtx, cancel := context.WithTimeout(ctx, time.Second*1)
		var attrs []map[string]string
		_ = chromedp.AttributesAll(fmt.Sprintf(`[%s]`, attrName), &attrs, chromedp.ByQueryAll).Do(tCtx)
		cancel()
		for _, attrMap := range attrs {
			tab.AddResultUrl(GET, attrMap[attrName], FromDOM)
		}
	}
}

func (tab *task) collectObjectLinks() {
	defer tab.collectLinkWG.Done()
	ctx := tab.GetExecutor()
	// 收集 object[data] links
	tCtx, cancel := context.WithTimeout(ctx, time.Second*1)
	defer cancel()
	var attrs []map[string]string
	_ = chromedp.AttributesAll(`object[data]`, &attrs, chromedp.ByQueryAll).Do(tCtx)
	for _, attrMap := range attrs {
		tab.AddResultUrl(GET, attrMap["data"], FromDOM)
	}
}

func (tab *task) collectCommentLinks() {
	defer tab.collectLinkWG.Done()
	ctx := tab.GetExecutor()
	// 收集注释中的链接
	var nodes []*cdp.Node
	tCtxComment, cancel := context.WithTimeout(ctx, time.Second*1)
	defer cancel()
	commentErr := chromedp.Nodes(`//comment()`, &nodes, chromedp.BySearch).Do(tCtxComment)
	if commentErr != nil {
		return
	}
	urlRegex := regexp.MustCompile(URLRegex)
	for _, node := range nodes {
		content := node.NodeValue
		urlList := urlRegex.FindAllString(content, -1)
		for _, url := range urlList {
			tab.AddResultUrl(GET, url, FromComment)
		}
	}
}

type Result struct {
	ReqList       []*http.Request // 返回的同域名结果
	AllReqList    []*http.Request // 所有域名的请求
	AllDomainList []string        // 所有域名列表
	SubDomainList []string        // 子域名列表
	resultLock    sync.Mutex      // 合并结果时加锁
}

type TaskConfig struct {
	MaxCrawlCount           int    // 最大爬取的数量
	MaxDepth                int    // 最大爬取深度
	FilterMode              string // simple、smart、strict
	ExtraHeaders            map[string]any
	ExtraHeadersString      string
	AllDomainReturn         bool // 全部域名收集
	SubDomainReturn         bool // 子域名收集
	IncognitoContext        bool // 开启隐身模式
	NoHeadless              bool // headless模式
	DomContentLoadedTimeout time.Duration
	TabRunTimeout           time.Duration     // 单个标签页超时
	PathByFuzz              bool              // 通过字典进行Path Fuzz
	FuzzDictPath            string            //Fuzz目录字典
	PathFromRobots          bool              // 解析Robots文件找出路径
	MaxTabsCount            int               // 允许开启的最大标签页数量 即同时爬取的数量
	ChromiumPath            string            // Chromium的程序路径  `/home/zhusiyu1/chrome-linux/chrome`
	EventTriggerMode        string            // 事件触发的调用方式： 异步 或 顺序
	EventTriggerInterval    time.Duration     // 事件触发的间隔
	BeforeExitDelay         time.Duration     // 退出前的等待时间，等待DOM渲染，等待XHR发出捕获
	EncodeURLWithCharset    bool              // 使用检测到的字符集自动编码URL
	IgnoreKeywords          []string          // 忽略的关键字，匹配上之后将不再扫描且不发送请求
	Proxy                   string            // 请求代理
	CustomFormValues        map[string]string // 自定义表单填充参数
	CustomFormKeywordValues map[string]string // 自定义表单关键词填充内容
}

type tabTask struct {
	crawlerTask *Crawler
	depth       int // 当前爬行深度
	browser     *Browser
	req         *http.Request
	pool        *ants.Pool

	Ctx                        *context.Context
	Cancel                     context.CancelFunc
	NavigateReq                http.Request
	NavigateReqRedirectionFlag bool
	ExtraHeaders               map[string]any
	//ResultList                 []*http.Request
	TopFrameId       string
	LoaderID         string
	NavNetworkID     string
	PageCharset      string
	PageBindings     map[string]any
	NavDone          chan int
	FoundRedirection bool
	DocBodyNodeId    cdp.NodeID
	config           TabConfig
	lock             sync.Mutex

	WG            sync.WaitGroup //当前Tab页的等待同步计数
	collectLinkWG sync.WaitGroup
	loadedWG      sync.WaitGroup //Loaded之后的等待计数
	formSubmitWG  sync.WaitGroup //表单提交完毕的等待计数
	removeLis     sync.WaitGroup //移除事件监听
	domWG         sync.WaitGroup //DOMContentLoaded 的等待计数
	fillFormWG    sync.WaitGroup //填充表单任务
}

/*
*
根据请求列表生成tabTask协程任务列表
*/
func (c *Crawler) generateTabTask(req *http.Request, depth int) *task {
	t := task{
		crawlerTask: c,
		browser:     c.Browser,
		req:         req,
		depth:       depth,
	}
	return &t
}

/*
*
开始当前任务
*/
func (t *Crawler) BrowserTaskRun() {

}

/*
*
单个运行的tab标签任务，实现了workpool的接口
*/
func (t *task) Task() {
	defer t.crawlerTask.taskWG.Done()

	navigateReq := *t.req
	config := TabConfig{
		TabRunTimeout:           t.crawlerTask.config.TaskConfig.TabRunTimeout,
		DomContentLoadedTimeout: t.crawlerTask.config.TaskConfig.DomContentLoadedTimeout,
		EventTriggerMode:        t.crawlerTask.config.TaskConfig.EventTriggerMode,
		EventTriggerInterval:    t.crawlerTask.config.TaskConfig.EventTriggerInterval,
		BeforeExitDelay:         t.crawlerTask.config.TaskConfig.BeforeExitDelay,
		EncodeURLWithCharset:    t.crawlerTask.config.TaskConfig.EncodeURLWithCharset,
		IgnoreKeywords:          t.crawlerTask.config.TaskConfig.IgnoreKeywords,
		CustomFormValues:        t.crawlerTask.config.TaskConfig.CustomFormValues,
		CustomFormKeywordValues: t.crawlerTask.config.TaskConfig.CustomFormKeywordValues,
	}
	t.ExtraHeaders = map[string]any{}
	var DOMContentLoadedRun = false
	t.Ctx, t.Cancel = t.browser.NewTab(config.TabRunTimeout)

	// 从 HTTPClientOptions.Headers 读取配置中所有自定义 headers（由 WroteBack 从 DefaultHeaders 转换而来）
	if t.crawlerTask.config.HTTPClientOptions != nil {
		for key, values := range t.crawlerTask.config.HTTPClientOptions.Headers {
			if len(values) > 0 {
				navigateReq.Header.Set(key, values[0])
				// Cookie 不能通过 SetExtraHTTPHeaders 设置，Chrome CDP 有独立的 Cookie 管理，会冲突导致事件解析报错
				if key != "Host" && key != "Cookie" {
					t.ExtraHeaders[key] = values[0]
				}
			}
		}
		// 兼容：如果 WroteBack 未被调用，从 DefaultHeaders 读取
		for key, value := range t.crawlerTask.config.HTTPClientOptions.DefaultHeaders {
			if _, exists := t.ExtraHeaders[key]; !exists {
				navigateReq.Header.Set(key, value)
				if key != "Host" && key != "Cookie" {
					t.ExtraHeaders[key] = value
				}
			}
		}
	}
	t.NavigateReq = navigateReq
	t.config = config
	t.NavDone = make(chan int)
	t.DocBodyNodeId = 0

	// 设置请求拦截监听
	chromedp.ListenTarget(*t.Ctx, func(v any) {
		switch v := v.(type) {
		// 根据不同的事件 选择执行对应的动作
		case *network.EventRequestWillBeSent:
			if string(v.RequestID) == string(v.LoaderID) && v.Type == "Document" && t.TopFrameId == "" {
				t.LoaderID = string(v.LoaderID)
				t.TopFrameId = string(v.FrameID)
			}

		// 请求发出时暂停 即 请求拦截
		case *fetch.EventRequestPaused:

			t.WG.Add(1)
			go t.InterceptRequest(v)

		// 解析所有JS文件中的URL并添加到结果中
		// 解析HTML文档中的URL
		// 查找当前页面的编码
		case *network.EventResponseReceived:
			if v.Response.MimeType == "application/javascript" ||
				v.Response.MimeType == "text/html" ||
				v.Response.MimeType == "application/json" ||
				v.Response.MimeType == "application/xml" ||
				strings.HasSuffix(v.Response.URL, "/robots.txt") ||
				strings.HasSuffix(v.Response.URL, "/sitemap.xml") {
				t.WG.Add(1)
				go t.ParseResponseURL(v)
			}
			if v.RequestID.String() == t.NavNetworkID {
				t.WG.Add(1)
				go t.GetContentCharset(v)
			}
		case *network.EventWebSocketFrameError:
			logger.Infof("EventWebSocketFrameError")
		// 处理后端重定向 3XX
		case *network.EventResponseReceivedExtraInfo:
			if v.RequestID.String() == t.NavNetworkID {
				t.WG.Add(1)
				go t.HandleRedirectionResp(v)
			}
		//case *network.EventLoadingFailed:
		//	logger.Error("EventLoadingFailed ", v.ErrorText)
		// 401 407 要求认证 此时会阻塞当前页面 需要处理解决
		case *fetch.EventAuthRequired:
			t.WG.Add(1)
			go t.HandleAuthRequired(v)

		// DOMContentLoaded
		// 开始执行表单填充 和 执行DOM节点观察函数 只执行一次
		case *page.EventDomContentEventFired:
			if DOMContentLoadedRun {
				return
			}
			DOMContentLoadedRun = true
			t.WG.Add(1)
			go t.AfterDOMRun()
		// Loaded
		case *page.EventLoadEventFired:
			if DOMContentLoadedRun {
				return
			}
			DOMContentLoadedRun = true
			t.WG.Add(1)
			go t.AfterDOMRun()

		// close Dialog
		case *page.EventJavascriptDialogOpening:
			t.WG.Add(1)
			go t.dismissDialog()

		// handle expose function
		case *runtime.EventBindingCalled:
			t.WG.Add(1)
			go t.HandleBindingCalled(v)
		}
	})

	t.Start()
}

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

	return nil
}

func (c *Crawler) handleBrowserTask(t *task) {
	logger.Infof("browser crawl %s %s", t.req.Method, t.req.GetURL().String())

	c.taskWG.Add(1)
	t.Task()

	data := t.req.GetRawBody()
	resp, err := t.crawlerTask.Client.DoRaw(t.req)
	if err != nil {
		// 处理错误
		t.crawlerTask.handleErr(err)
		logger.Errorf("%s, %s, %s", t.req.Method, t.req.GetURL().String(), string(data))
		return
	}
	if len(data) != 0 {
		logger.Infof("%s", string(data))
	}
	flow := http.Flow{
		Request:  t.req,
		Response: resp,
	}
	t.crawlerTask.handleFlow(&flow)
	logger.Infof("send req task %s %s", t.req.Method, t.req.GetURL().String())

	return
}

func (*Crawler) findURLAndCreateNewTask() {

}

func (*Crawler) createTaskByURL() {

}
