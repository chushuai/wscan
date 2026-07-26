/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package ctrl

import (
	"fmt"
	"os"
	"sort"
	"strings"
	"time"
	"wscan/core/http"
	"wscan/core/model"
	"wscan/core/plugins"
	"wscan/core/plugins/base"
	"wscan/core/plugins/helper"
	"wscan/core/plugins/helper/knowledge"
	"wscan/core/resource"
	"wscan/core/reverse"
	"wscan/core/utils"
	"wscan/core/utils/checker"
	"wscan/core/utils/checker/filter"
	"wscan/core/utils/log"
	"wscan/core/utils/printer"
	"wscan/core/utils/printer/nice"

	"github.com/kataras/pio"
	"github.com/panjf2000/ants/v2"
	"golang.org/x/net/context"
)

// Dispatcher manages plugin lifecycle and event dispatching. It handles
// plugin initialization, execution, and release, as well as event processing
// and tree structure construction for vulnerability detection.
type Dispatcher struct {
	plugins       []base.Plugin
	pluginConfig  map[string]base.PluginConfigInterface
	config        *Config
	httpStat      *http.Statistics
	httpClient    *http.Client
	apolloBase    *base.ApolloBase
	fingerCount   map[int]int
	requestFilter *checker.RequestChecker
	serviceFilter *checker.ServiceChecker
	ctx           context.Context
	cancel        func()
	reactor       *ants.Pool // 池子
	root          *Node      // 执行节点，树结构, 插件的执行节点，子节点对应的是子指纹
	evBus         *EventBus
	nextCounter   int32
	done          chan struct{}
	retestErr     error
	hasRun        bool
	tempDir       string
	bf            *filter.BadgerFilter
	republishCh   chan *http.Flow
}

// TODO: implement DumpSvg
func (d *Dispatcher) DumpSvg() string {
	return ""
}

func (d *Dispatcher) EnabledPlugins() {
	for _, p := range d.plugins {
		fmt.Println(p)
		//if p.Enabled() {
		//	log.Infof("enabled plugin: %s", p.Name())
		//}
	}
}

func (d *Dispatcher) Init(noScan bool) error {
	// 初始化evBus
	d.evBus = NewEventBusWithAsyncPool(d.reactor)
	d.ctx, d.cancel = context.WithCancel(context.Background())
	allPlugins := plugins.All()
	for _, p := range allPlugins {
		if pc := d.pluginConfig[p.DefaultConfig().BaseConfig().Name]; pc != nil {
			if pc.BaseConfig().Enabled {
				p.Init(d.ctx, pc, d.apolloBase)
				d.plugins = append(d.plugins, p)
			} else {
				log.Infof("plugin %s is disabled", pc.BaseConfig().Name)
			}
		} else {
			p.Init(d.ctx, p.DefaultConfig(), d.apolloBase)
			d.plugins = append(d.plugins, p)
			log.Warningf("plugin %s is not configured, using default config", p.DefaultConfig().BaseConfig().Name)
		}
	}

	log.Infof("plugins num = %d", len(d.plugins))
	d.buildTree()

	// d.rmNode()
	d.traversalTree(func(node Node) {
		runner := BasicRunner{check: node.Data.CheckAction,
			biBase:  d.apolloBase,
			exec:    node.Data.ExecAction,
			binding: node.Data.Binding}
		if utils.StringIIn(node.Data.Channel, []string{"web-generic", "web-directory", "web-path", "website", "javascript"}) {
			d.evBus.SubscribeAsync(node.Data.Channel, runner.Run, false)
		}
	})

	return nil
}
func (d *Dispatcher) Release() {
	d.reactor.Release()

	if d.apolloBase.Reverse != nil {
		d.apolloBase.Reverse.Close()
	}
}

func (d *Dispatcher) Retest() {

	// d.evBus.Publish(context.Background(), "retest", nil)
}

// processFlow 处理单个 flow：更新统计、输出爬虫结果、知识库处理、分发到事件总线
func (d *Dispatcher) processFlow(b resource.Resource) {
	d.httpClient.Stater().TargetFound()
	if flow, ok := b.(*http.Flow); ok {
		flow.Request = flow.Request.DeepClone()
		d.apolloBase.Output.Print(&model.CrawlerResult{
			Url:     flow.Request.URL().String(),
			Method:  flow.Request.Method,
			Headers: flow.Request.GetHeaderMap(),
			Data:    string(flow.Request.GetRawBody()),
		})
	}
	d.apolloBase.KDB.Process(d.ctx, b)
	d.publishToNode(b)
	d.httpClient.Stater().TargetScanned()
}

// 调度开始运行
func (d *Dispatcher) Run(taskChan chan resource.Resource, noScan bool) {

	if d.hasRun {
		log.Warn("dispatcher has already run")
		return
	}
	d.hasRun = true
	d.done = make(chan struct{})

	d.ctx, d.cancel = context.WithCancel(context.Background())
	defer close(d.done)
	defer d.cancel()
	go d.statistic(d.ctx)

loop:
	for {
		select {
		case task, ok := <-taskChan:
			if !ok {
				// taskChan 关闭，排空 republishCh 中已入队的 flow 后退出 select 循环
				for {
					select {
					case f := <-d.republishCh:
						d.processFlow(f)
					default:
						break loop
					}
				}
			}
			if noScan {
				d.httpClient.Stater().TargetFound()
				if flow, ok := task.(*http.Flow); ok {
					d.apolloBase.Output.Print(&model.CrawlerResult{
						Url:     flow.Request.URL().String(),
						Method:  flow.Request.Method,
						Headers: flow.Request.GetHeaderMap(),
						Data:    string(flow.Request.GetRawBody()),
					})
				}
				continue
			}
			d.processFlow(task)
		case f := <-d.republishCh:
			d.processFlow(f)
		}
	}

	d.Wait(d.ctx)

	// PostScan phase: verify stored vulnerabilities (re-visits reflection
	// points and waits for delayed OOB callbacks)
	d.postScanPhase(d.ctx)

	if d.bf != nil {
		d.bf.Close()
	}
	err := os.RemoveAll(d.tempDir)
	if err != nil {
		log.Errorf("Failed to remove temporary directory: %v\n", err)
	}

}
func (d *Dispatcher) Wait(context.Context) {
	for {
		d.evBus.WaitAsync()
		if d.apolloBase.TaskRunner != nil {
			d.apolloBase.TaskRunner.WaitAll()
		}
		// 排空 republishCh：插件（如 swagger）发现新端点后会通过 PublishFlow 发到此处
		drained := false
		for {
			select {
			case f := <-d.republishCh:
				d.processFlow(f)
				drained = true
			default:
				goto done
			}
		}
	done:
		if !drained {
			break
		}
	}
}

// postScanPhase runs after the main scan completes. It re-visits reflection
// points collected during scanning to verify if injected payloads were
// persisted (stored XSS, stored SQLi, stored RCE via OOB callbacks).
func (d *Dispatcher) postScanPhase(ctx context.Context) {
	psConfig := d.config.PostScan
	if psConfig == nil || !psConfig.Enabled {
		log.Info("[PostScan] PostScan phase is disabled, skipping")
		return
	}

	records := d.apolloBase.GetReflectionRecords()
	if len(records) == 0 && d.apolloBase.Reverse == nil {
		log.Info("[PostScan] No reflection records and no reverse platform, skipping")
		return
	}

	maxDuration := time.Duration(psConfig.MaxDuration) * time.Second
	reverseWait := time.Duration(psConfig.ReverseWait) * time.Second

	// Enforce the 20% budget: PostScan should not exceed 20% of the main scan time.
	// Since we cannot know the exact main scan duration here, we use the configured
	// max_duration as the upper bound and let the verifier respect it.
	if maxDuration <= 0 {
		maxDuration = 60 * time.Second
	}
	if reverseWait <= 0 {
		reverseWait = 120 * time.Second
	}

	verifier := base.NewStoredVulnVerifier(d.apolloBase, maxDuration, reverseWait)
	verifier.VerifyAll(ctx, records)
}

func (d *Dispatcher) buildTree() {
	d.root = &Node{ID: "root", Level: 0, Parent: nil}
	// for each plugin, add its fingerprint to the tree
	var DisabledPluginDueToNoReverseServerConfig = []string{}
	for _, plugin := range d.plugins {
		if plugin.DefaultConfig().BaseConfig().IsAdvanced {
			for _, finger := range plugin.Fingers() {
				d.apolloBase.KDB.AddCheckRule(func() func(context.Context, resource.Resource) error {
					runner := BasicRunner{check: finger.CheckAction,
						biBase:  d.apolloBase,
						exec:    finger.ExecAction,
						binding: finger.Binding}
					return func(ctx context.Context, res resource.Resource) error {
						runner.Run(res)
						return nil
					}
				}())
			}
		} else {
			n1 := NewNodeFromParent(d.root)
			n1.ID = plugin.GetConfig().BaseConfig().Name
			for _, finger := range plugin.Fingers() {
				if finger.NeedReverse && d.apolloBase.Reverse == nil {
					DisabledPluginDueToNoReverseServerConfig = append(DisabledPluginDueToNoReverseServerConfig, finger.Binding.Plugin)
					continue
				}
				n2 := NewNodeFromParent(n1)
				n2.Data = finger
				n2.ID = finger.Binding.ID
			}
		}
	}
	if len(DisabledPluginDueToNoReverseServerConfig) > 0 {
		nice.PioPrinter.Print(pio.Rich("These plugins will be disabled as reverse server is not configured, check out the reference to fix this error.\nPlugins:\n", pio.Red))
		for _, pluginName := range DisabledPluginDueToNoReverseServerConfig {
			nice.PioPrinter.Print(pio.Rich(fmt.Sprintf("\t%s\n", pluginName), pio.Red))
		}
	}
	// sort the tree in ascending order of the number of child nodes
	d.traversalTree(func(node Node) {
		sort.Slice(node.Child, func(i, j int) bool {
			return len(node.Child[i].Child) < len(node.Child[j].Child)
		})
	})

}

// func (*Dispatcher) findNode()
func (d *Dispatcher) findNode(vb *model.VulnBinding) *Node {
	if d.root == nil {
		return nil
	}
	queue := []*Node{d.root}
	for len(queue) > 0 {
		currentNode := queue[0]
		queue = queue[1:]
		if currentNode.Data.Binding == vb {
			return currentNode
		}
		for _, childNode := range currentNode.Child {
			queue = append(queue, childNode)
		}
	}
	return nil
}

//func (*Dispatcher) makeLeftNodeDone()

// 将左侧的节点标记为已完成。具体来说，它会遍历当前节点的父节点的所有子节点，然后将所有需要独立测试的子节点以及所有依赖于当前节点
func (d *Dispatcher) makeLeftNodeDone(node *Node) {
	for _, n := range node.Child {
		d.makeLeftNodeDone(n)
	}
	node.Data.NeedStandalone = false
	node.Data.NeedTransaction = false
	node.Data.NeedReverse = false

}

func (d *Dispatcher) publishToNode(b resource.Resource) {
	req := b.(*http.Flow).Request
	u := req.URL()
	if req.IsJavaScript() {
		d.evBus.Publish("javascript", b)
		return
	}
	if u.RawQuery == "" && u.Fragment == "" {
		if u.Path == "" || strings.HasSuffix(u.Path, "/") {
			if d.requestFilter.TargetURL(req.URL()).IsNewWebsiteDir() != nil {
				log.Infof("publishToNode web-directory: %s", req.URL().String())
				d.evBus.Publish("web-directory", b)
			}
		}
		// website 仅在网站纯根路径（无查询参数、无Fragment）时触发
		// 避免 http://example.com/?a=b 或 http://example.com/#a 误触发
		if u.Path == "" || u.Path == "/" {
			if d.requestFilter.TargetURL(req.URL()).IsNewWebsite() != nil {
				d.evBus.Publish("website", b)
			}
		}
	}

	if d.requestFilter.TargetURL(req.URL()).IsNewWebsitePath() != nil {
		d.evBus.Publish("web-path", b)
	}
	d.evBus.Publish("web-generic", b)

}

func (d *Dispatcher) statistic(ctx context.Context) {
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s := d.httpStat.Stat()
			// 没有发现任何 URL 时，跳过输出，避免空闲时显示无意义的统计
			if s.FoundNumber == 0 {
				continue
			}
			d.apolloBase.Output.Print(&model.StatisticRecord{
				NumFoundUrls:            s.FoundNumber,
				NumScannedUrls:          s.ScannedNumber,
				NumSentHTTPRequests:     s.RequestNumber,
				AverageResponseTime:     s.AverageResponseTime,
				RatioFailedHTTPRequests: s.RatioFailedHTTPRequests,
			})

		}
	}
}

func (d *Dispatcher) traversalTree(cb func(node Node)) {
	// 从根节点开始遍历整个树
	stack := []*Node{d.root}

	for len(stack) > 0 {
		// 取出栈顶节点
		node := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		// 如果当前节点是叶子节点，将它的 Data 推送到订阅者
		if len(node.Child) == 0 && node.Data != nil {
			cb(*node)
			continue
		}

		// 否则将当前节点的所有子节点依次入栈
		for _, child := range node.Child {
			stack = append(stack, child)
		}
	}
}
func (*Dispatcher) trimHeader(headers map[string][]string) {
	// Remove conditional and caching headers that should not be sent in scanner requests
	dropHeaders := []string{
		"ETag",
		"If-Modified-Since",
		"If-Match",
		"If-None-Match",
		"If-Range",
		"If-Unmodified-Since",
	}
	for _, h := range dropHeaders {
		delete(headers, h)
	}
}

func NewDispatcher(cfg *Config, output printer.Printer, reverse *reverse.Reverse) *Dispatcher {
	d := Dispatcher{config: cfg}
	var err error
	if cfg.Parallel <= 0 {
		log.Fatalf("Parallel must be greater than or equal to 1")
	}
	d.reactor, err = ants.NewPool(cfg.Parallel, ants.WithNonblocking(false))
	if err != nil {
		return nil
	}

	d.tempDir, err = os.MkdirTemp("", "webscan_badger")
	if err != nil {
		log.Fatal(err)
	}
	log.Infof("Temporary directory name:%s", d.tempDir)
	d.bf, err = filter.NewBadgerFilter(d.tempDir)
	if err != nil {
		log.Fatal(err)
	}

	cfg.HTTP.TLSSkipVerify = true

	d.pluginConfig = cfg.Plugins
	d.requestFilter = checker.NewRequestChecker(cfg.Filter, d.bf)
	d.httpClient = http.NewClientWithOptions(d.config.HTTP)
	d.httpStat = d.httpClient.Stater()
	d.republishCh = make(chan *http.Flow, 4096)
	d.apolloBase = &base.ApolloBase{Output: output,
		KDB:          knowledge.NewKnowledgeDB(d.bf),
		FilterConfig: cfg.Filter,
		VulnFilter:   cfg.VulnFilter,
		// FilterContainer: d.requestFilter,
		HTTPClient: d.httpClient,
		Reverse:    reverse,
		TaskRunner: base.NewTaskRunner(d.reactor),
		PublishFlow: func(f *http.Flow) {
			select {
			case d.republishCh <- f:
			default:
				log.Warnf("republish channel full, dropping flow: %s", f.Request.URL().String())
			}
		},
	}
	if d.apolloBase.Reverse != nil {
		helper.Reverse = d.apolloBase.Reverse
	}
	return &d

}

func NewNodeFromParent(parent *Node) *Node {
	node := &Node{
		Level:  parent.Level + 1,
		Parent: parent,
	}
	parent.Child = append(parent.Child, node)
	return node

}
