/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package base

import (
	"path/filepath"
	"sync"
	"time"
	"wscan/core/http"
	"wscan/core/model"
	"wscan/core/plugins/helper/knowledge"
	"wscan/core/resource"
	"wscan/core/reverse"
	"wscan/core/utils/checker"
	"wscan/core/utils/checker/filter"
	logger "wscan/core/utils/log"
	"wscan/core/utils/printer"

	"golang.org/x/net/context"
)

// ReflectionRecord captures a reflection point discovered during the main scan
// phase. These records are used by the PostScan phase to verify whether injected
// payloads were persisted (stored XSS, stored SQLi, stored RCE).
type ReflectionRecord struct {
	URL          string
	Method       string
	Parameter    string
	Payload      string
	PluginName   string
	VulnType     string // "xss", "sqli", "cmdi"
	Timestamp    time.Time
	ReverseToken string // for OOB verification
}

// ApolloBase provides shared infrastructure for vulnerability detection plugins,
// including HTTP client, reverse connection, knowledge DB, and output handling.
type ApolloBase struct {
	HTTPClient        *http.Client
	KDB               *knowledge.KnowledgeDB
	Reverse           *reverse.Reverse
	Output            printer.Printer
	FilterContainer   filter.Filter
	FilterConfig      *checker.RequestCheckerConfig
	VulnFilter        *model.VulnFilterConfig
	ctx               context.Context
	cancel            func()
	clone             bool
	vuln              *model.Vuln // 漏洞绑定，可以通过漏洞名找到对应的插件
	PublishFlow       func(f *http.Flow)
	TaskRunner        *TaskRunner
	ReflectionRecords []*ReflectionRecord
	recordsMu         sync.Mutex
}

// RecordReflection registers a reflection point for later PostScan verification.
// Plugins should call this when they inject a payload that might be stored
// (e.g., stored XSS, stored SQLi, stored RCE).
func (ab *ApolloBase) RecordReflection(rec *ReflectionRecord) {
	ab.recordsMu.Lock()
	defer ab.recordsMu.Unlock()
	ab.ReflectionRecords = append(ab.ReflectionRecords, rec)
}

// GetReflectionRecords returns a snapshot of all recorded reflection points.
func (ab *ApolloBase) GetReflectionRecords() []*ReflectionRecord {
	ab.recordsMu.Lock()
	defer ab.recordsMu.Unlock()
	result := make([]*ReflectionRecord, len(ab.ReflectionRecords))
	copy(result, ab.ReflectionRecords)
	return result
}

// Apollo wraps ApolloBase with per-target state for a single detection run.
type Apollo struct {
	sync.Mutex
	*ApolloBase
	tempDB  *sync.Map
	binding *model.VulnBinding // 漏洞绑定，可以通过漏洞名找到对应的插件
	target  resource.Resource  // 要扫描的目标，一个http的flow
}

func (*ApolloBase) Close() {

}

func (ab *ApolloBase) GetVulnToTest() *model.Vuln {
	return ab.vuln
}

func (*ApolloBase) IsRetesting() bool {
	return false
}

func (*ApolloBase) NewBrowser(int) error {
	return nil
}

func (ab *ApolloBase) NewRequestChecker() (*checker.RequestChecker, error) {
	return checker.NewRequestChecker(ab.FilterConfig, ab.FilterContainer), nil
}

func (ab *ApolloBase) NewURLChecker() (*checker.URLChecker, error) {
	return checker.NewURLChecker(&ab.FilterConfig.URLCheckerConfig, ab.FilterContainer), nil
}

func (*ApolloBase) StatusLogError(v string) {
	logger.Error(v)
}

func (*ApolloBase) StatusLogInfo(v string) {
	logger.Info(v)
}

func (*ApolloBase) StatusLogWarn(v string) {
	logger.Warn(v)
}

func (b *ApolloBase) WithClone(clone bool) *ApolloBase {
	b.clone = clone
	return b
}

func (b *ApolloBase) WithContext(ctx context.Context) *ApolloBase {
	b.ctx = ctx
	return b
}

func (b *ApolloBase) WithVuln(v *model.Vuln) *ApolloBase {
	b.vuln = v
	return b
}

func (ab *ApolloBase) SubmitTask(task AsyncTask) error {
	if ab.TaskRunner == nil {
		task.Fn() // 降级为同步执行
		return nil
	}
	return ab.TaskRunner.SubmitTask(task)
}

func (a *Apollo) Close() {
	a.ApolloBase.Close()
}

func (a *Apollo) GetVulnToTest() *model.Vuln {
	return a.ApolloBase.GetVulnToTest()
}

func (Apollo) IsRetesting() bool {
	return false
}

func (Apollo) NewBrowser(int) error {
	return nil
}

func (a *Apollo) NewRequestChecker() (*checker.RequestChecker, error) {
	return a.ApolloBase.NewRequestChecker()
}

func (a *Apollo) NewURLChecker() (*checker.URLChecker, error) {
	return a.ApolloBase.NewURLChecker()
}

func (a *Apollo) WithClone(clone bool) *ApolloBase {
	a.ApolloBase.clone = clone
	return a.ApolloBase
}
func (a *Apollo) WithContext(ctx context.Context) *ApolloBase {
	a.ApolloBase.ctx = ctx
	return a.ApolloBase
}

func (b *Apollo) WithVuln(v *model.Vuln) *ApolloBase {
	b.vuln = v
	b.binding = v.Binding
	return b.ApolloBase
}

func (b *Apollo) GetTargetFlow() *http.Flow {
	return b.target.DeepClone().(*http.Flow)
}

func (a *Apollo) GetTargetService() *resource.Service {
	if target, ok := a.target.(*resource.Service); ok {
		return target
	}
	return nil
}

func (a *Apollo) NewServiceVuln(svc *resource.Service) *model.Vuln {
	return &model.Vuln{
		Binding:    a.binding,
		Extra:      make(map[string]any),
		Flow:       nil,
		CreateTime: time.Now().Unix(),
	}
}

func (b *Apollo) NewWebVuln(req *http.Request, res *http.Response, p *http.Parameter) *model.Vuln {
	return b.NewWebVulnFromFlow([]*http.Flow{{Request: req, Response: res}}, p)
}

func (b *Apollo) NewWebVulnFromFlow(flow []*http.Flow, param *http.Parameter) *model.Vuln {
	return &model.Vuln{
		Param:      param,
		Flow:       flow,
		Binding:    b.binding,
		Extra:      make(map[string]any),
		CreateTime: time.Now().Unix(),
	}
}

func (b *Apollo) OutputVuln(v *model.Vuln) {
	if !b.shouldOutputVuln(v) {
		return
	}

	b.Output.Print(v)
}

func (b *Apollo) shouldOutputVuln(v *model.Vuln) bool {
	if b.VulnFilter == nil {
		return true
	}

	// Check include list: if specified, only output vulns matching the list
	if len(b.VulnFilter.IncludeVulns) > 0 {
		matched := false
		for _, pattern := range b.VulnFilter.IncludeVulns {
			if m, _ := filepath.Match(pattern, v.Binding.ID); m {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}

	// Check exclude list
	for _, pattern := range b.VulnFilter.ExcludeVulns {
		if m, _ := filepath.Match(pattern, v.Binding.ID); m {
			return false
		}
	}

	// Check min severity
	if b.VulnFilter.MinSeverity != "" {
		minLevel := model.SeverityLevel(b.VulnFilter.MinSeverity)
		vulnSeverity := v.Binding.Severity
		if vulnSeverity == "" {
			vulnSeverity = model.SeverityInfo
		}
		vulnOrder, ok1 := model.SeverityOrder[vulnSeverity]
		minOrder, ok2 := model.SeverityOrder[minLevel]
		if ok1 && ok2 && vulnOrder < minOrder {
			return false
		}
	}

	return true
}

func (a *Apollo) Set(key string, value any) {
	a.tempDB.Store(key, value)
}

func NewApollo(target resource.Resource) *Apollo {
	return &Apollo{
		ApolloBase: &ApolloBase{},
		tempDB:     &sync.Map{},
		target:     target,
	}
}
