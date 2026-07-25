/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package dirscan

import (
	"bufio"
	"context"
	"strings"
	"sync"

	"github.com/google/cel-go/cel"
	"github.com/pkg/errors"
	"os"

	_ "embed"
	"gopkg.in/yaml.v2"

	"wscan/core/http"
	"wscan/core/model"
	"wscan/core/plugins/base"
	"wscan/core/plugins/helper"
	"wscan/core/utils"
	"wscan/core/utils/checker"
	logger "wscan/core/utils/log"
)

// bodySimilarity returns a similarity ratio between two strings (0.0-1.0)
func bodySimilarity(a, b string) float64 {
	if a == b {
		return 1.0
	}
	lenA, lenB := len(a), len(b)
	if lenA == 0 && lenB == 0 {
		return 1.0
	}
	if lenA == 0 || lenB == 0 {
		return 0.0
	}
	minLen, maxLen := lenA, lenB
	if minLen > maxLen {
		minLen, maxLen = maxLen, minLen
	}
	lengthRatio := float64(minLen) / float64(maxLen)
	if lengthRatio < 0.5 {
		return lengthRatio * 0.5
	}
	common := 0
	minCheck := minLen
	if minCheck > 512 {
		minCheck = 512
	}
	for i := 0; i < minCheck; i++ {
		if a[i] == b[i] {
			common++
		}
	}
	prefixRatio := float64(common) / float64(minCheck)
	return 0.5*lengthRatio + 0.5*prefixRatio
}

// notFoundKeywords are common keywords found in custom 404 pages
var notFoundKeywords = []string{"not found", "not exist", "no found", "page not found", "找不到", "页面不存在", "file not found"}

// baselineCache stores the random-path baseline response per host,
// so Rule.ExecAction can access it for false-positive filtering.
var (
	baselineMutex sync.Mutex
	baselineCache = make(map[string]*http.Response)
)

// setBaseline stores the baseline response for a host.
func setBaseline(host string, resp *http.Response) {
	baselineMutex.Lock()
	defer baselineMutex.Unlock()
	baselineCache[host] = resp
}

// getBaseline retrieves the baseline response for a host.
func getBaseline(host string) *http.Response {
	baselineMutex.Lock()
	defer baselineMutex.Unlock()
	return baselineCache[host]
}

// isFalsePositive checks if a dirscan response is a false positive by comparing against a 404 baseline
func isFalsePositive(resp *http.Response, baseline *http.Response) bool {
	if baseline == nil {
		return false
	}
	// 1. Body identical to baseline → same page served for any URL
	if resp.Text == baseline.Text {
		return true
	}
	// 2. Body highly similar to baseline → likely the same template page
	if bodySimilarity(resp.Text, baseline.Text) > 0.8 {
		return true
	}
	// 3. Custom 404 page returning 200: check for 404 keywords in body
	lower := strings.ToLower(resp.Text)
	for _, kw := range notFoundKeywords {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}

type Category struct {
	Name  string `yaml:"name"`
	Title string `yaml:"title"`
}

type Config struct {
	base.PluginBaseConfig `json:",inline" yaml:",inline"`
	Depth                 int    `yaml:"depth" json:"depth" #:"检测深度，定义 http://t.com/a/ 深度为 1, http://t.com/a 深度为 0"`
	Dictionary            string `json:"dictionary" yaml:"dictionary" #:"自定义检测字典, 配置后将与内置字典**合并**"`
}

func (c *Config) BaseConfig() *base.PluginBaseConfig {
	return &c.PluginBaseConfig
}

type Dirscan struct {
	base.PluginMixinInitConfig
	base.PluginMixinClose
	ruleSet       *RuleSet
	notFoundMutex sync.Mutex
	notFoundCache map[string][]*http.Response
	depthMutex    sync.Mutex
	depthCache    map[string]error
	catchAllMutex sync.Mutex
	catchAllCache map[string]bool // per-host cache: true = catch-all detected, skip scan
}

type RuleSet struct {
	Version  string      `yaml:"version"`
	Category []*Category `yaml:"category"`
	Rules    []*Rule     `yaml:"rules"`
}

type Rule struct {
	Category   string      `yaml:"category"`
	Paths      []string    `yaml:"paths"`
	PathChan   chan string `yaml:"-"`
	Suffix     []string    `yaml:"suffix"`
	Expression string      `yaml:"expression"`
	Partial    bool        `yaml:"partial"` // 是否最作用与非跟目录
	Root       bool        `yaml:"root"`    // 是否最作用与根目录
	expCache   cel.Program
}

func (r *Rule) CheckAction(ctx context.Context, ab *base.Apollo) error {
	return nil
}

func (r *Rule) ExecAction(ctx context.Context, ab *base.Apollo) error {
	flow := ab.GetTargetFlow()

	// Get the baseline (random path) response from the package-level cache
	// for false-positive filtering. Catch-all detection is already done
	// in Check404 — if both random paths returned 200, ExecAction
	// won't even be called.
	baseline := getBaseline(flow.Request.URL().Host)

	for _, path := range r.Paths {
		if r.expCache == nil || path == "" {
			continue
		}
		rawUrl := utils.UrlJoinPath(flow.Request.URL().String(), path)
		request, err := http.NewRequest("GET", rawUrl, nil)
		if err != nil {
			return err
		}
		resp, err := ab.HTTPClient.Respond(context.Background(), request)
		if err != nil {
			return err
		}
		variableMap := make(map[string]any)
		protoResponse, _ := helper.ConvertHttpResponseToModelResponse(resp, 10)
		variableMap["response"] = protoResponse
		successVal, _, err := r.expCache.Eval(variableMap)
		if err != nil {
			logger.Error(err)
			continue
		}
		isVul, ok := successVal.Value().(bool)
		if !ok {
			isVul = false
		}
		if isVul {
			// Filter: custom 404 pages returning 200 (compare against random-path baseline)
			if isFalsePositive(resp, baseline) {
				continue
			}
			v := ab.NewWebVuln(request, resp, nil)
			if v != nil {
				v.SetTargetURL(request.URL())
				v.Payload = path
				ab.OutputVuln(v)
			}
		}
	}
	return nil
}

func (r *Rule) Finger() *base.Finger {
	return &base.Finger{
		CheckAction: r.CheckAction,
		ExecAction:  r.ExecAction,
		Channel:     "web-directory",
		Binding:     &model.VulnBinding{ID: r.Category, Plugin: r.Category, Category: r.Category, Severity: model.SeverityLow},
	}
}

func (r *Rule) RetestAction(ctx context.Context, ab *base.Apollo) error {
	return nil
}

func (r *Rule) detectPath() {

}

//go:embed "dirscan_rule.yml"
var ruleYaml []byte

type sourceMap struct {
	filter *checker.URLChecker
}

func (p *Dirscan) DefaultConfig() base.PluginConfigInterface {
	config := &Config{PluginBaseConfig: base.PluginBaseConfig{
		Name:    "dirscan",
		Enabled: true,
	}, Depth: 1}
	return config
}

func (p *Dirscan) Fingers() []*base.Finger {
	fingers := []*base.Finger{}
	if p.ruleSet == nil {
		return fingers
	}
	for _, rule := range p.ruleSet.Rules {
		if rule.expCache != nil {
			finger := rule.Finger()
			finger.CheckAction = func(r *Rule) func(ctx context.Context, ab *base.Apollo) error {
				return func(ctx context.Context, ab *base.Apollo) error {
					var err error
					if err = p.DepthCheck(ctx, ab); err != nil {
						return err
					}
					if err = r.CheckAction(ctx, ab); err != nil {
						return err
					}
					if err = p.Check404(ctx, ab); err != nil {
						return err
					}

					return p.DepthCheck(ctx, ab)
				}
			}(rule)
			fingers = append(fingers, finger)
		}
	}
	return fingers
}

func (p *Dirscan) DepthCheck(ctx context.Context, ab *base.Apollo) error {
	flow := ab.GetTargetFlow()
	depth := flow.Request.GetURLDepth()
	if p.GetConfig().(*Config).Depth != 0 && depth > p.GetConfig().(*Config).Depth {
		return errors.New("depth check failed")
	}
	p.depthMutex.Lock()
	defer p.depthMutex.Unlock()
	if err, exist := p.depthCache[flow.Request.URL().String()]; exist {
		return err
	}
	return nil
}

func (p *Dirscan) Check404(ctx context.Context, ab *base.Apollo) error {
	p.notFoundMutex.Lock()
	defer p.notFoundMutex.Unlock()
	flow := ab.GetTargetFlow()
	hostKey := flow.Request.URL().Host

	// Check catch-all cache first: if 2 random directories both returned 200,
	// this is a catch-all site and dirscan should be skipped entirely.
	if isCatchAll, exists := p.catchAllCache[hostKey]; exists {
		if isCatchAll {
			return errors.New("catch-all路由: 2个随机目录均返回200, 跳过dirscan")
		}
		// Not catch-all, continue with 404 check using cached responses
		if f, fExists := p.notFoundCache[hostKey]; fExists && len(f) > 0 {
			if f[0].StatusCode >= 400 && f[0].StatusCode <= 500 {
				return nil
			}
			return errors.New("无法识别404")
		}
	}

	// Send 2 random path requests to detect catch-all routing
	randPath1 := utils.RandLetters(16)
	randPath2 := utils.RandLetters(16)
	rawUrl1 := utils.UrlJoinPath(flow.Request.URL().String(), randPath1)
	rawUrl2 := utils.UrlJoinPath(flow.Request.URL().String(), randPath2)

	req1, err := http.NewRequest("GET", rawUrl1, nil)
	if err != nil {
		return err
	}
	resp1, err1 := ab.HTTPClient.Respond(context.Background(), req1)

	req2, err2 := http.NewRequest("GET", rawUrl2, nil)
	if err2 != nil {
		return err2
	}
	resp2, err2 := ab.HTTPClient.Respond(context.Background(), req2)

	// Cache the first random response for isFalsePositive comparison later
	if err1 == nil {
		p.notFoundCache[hostKey] = []*http.Response{resp1}
		setBaseline(hostKey, resp1)
	}

	// If BOTH random paths return 200, this is a catch-all site
	// Do NOT execute dirscan — all paths would match, producing only false positives
	if err1 == nil && err2 == nil &&
		resp1.StatusCode == 200 && resp2.StatusCode == 200 {
		p.catchAllCache[hostKey] = true
		logger.Debug("catch-all路由检测: %s 2个随机目录(%s, %s)均返回200, 跳过dirscan",
			hostKey, randPath1, randPath2)
		return errors.New("catch-all路由: 2个随机目录均返回200, 跳过dirscan")
	}

	p.catchAllCache[hostKey] = false

	// Standard 404 check: if the random path returned 4xx-5xx, 404 is identifiable
	if err1 == nil && resp1.StatusCode >= 400 && resp1.StatusCode <= 500 {
		return nil
	}

	return errors.New("无法识别404")
}

func (p *Dirscan) GetConfig() base.PluginConfigInterface {
	return p.PluginMixinInitConfig.GetConfig()
}

func (p *Dirscan) Init(ctx context.Context, pci base.PluginConfigInterface, ab *base.ApolloBase) error {
	logger.Debug("Dirscan init")
	p.PluginMixinInitConfig.Init(ctx, pci, ab)
	var ruleSet RuleSet
	err := yaml.Unmarshal(ruleYaml, &ruleSet)
	if err != nil {
		logger.Fatal(err)
	}
	seen := make(map[string]bool)
	c := p.GetConfig().(*Config)
	if c.Dictionary != "" && utils.FileExists(c.Dictionary) {
		urlFile, err := os.Open(c.Dictionary)
		if err == nil {
			defer urlFile.Close()
			scanner := bufio.NewScanner(urlFile)
			for scanner.Scan() {
				url := strings.TrimSpace(scanner.Text())
				if strings.HasPrefix(url, "/") {
					url = url[1:]
				}
				if url == "" || url == "/" {
					continue
				}
				if _, exist := seen[url]; !exist {
					ruleSet.Rules = append(ruleSet.Rules, &Rule{Paths: []string{url},
						Expression: "response.status == 200", Category: "dirscan/default"})
					seen[url] = true
				}

			}
		} else {
			logger.Error(err)
		}
	}
	for i := range ruleSet.Rules {
		ast, iss := helper.DefaultCelEnv.Compile(ruleSet.Rules[i].Expression)
		err = iss.Err()
		if err != nil {
			continue
		}
		prg, err := helper.DefaultCelEnv.Program(ast)
		if err != nil {
			continue
		}
		ruleSet.Rules[i].expCache = prg
		for j := range ruleSet.Rules[i].Paths {
			if strings.HasPrefix(ruleSet.Rules[i].Paths[j], "/") {
				ruleSet.Rules[i].Paths[j] = ruleSet.Rules[i].Paths[j][1:]
			}
		}
	}
	p.ruleSet = &ruleSet
	p.notFoundCache = make(map[string][]*http.Response)
	p.depthCache = make(map[string]error)
	p.catchAllCache = make(map[string]bool)
	return nil
}

func (p *Dirscan) Close() error {
	return nil
}
