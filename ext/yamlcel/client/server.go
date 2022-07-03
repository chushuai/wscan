package client

import (
	"bytes"
	"context"
	"embed"
	"github.com/kataras/golog"
	"io/ioutil"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"text/template"
)

type route struct {
	chain   *MutationChain
	rule    *MutationRule
	handler http.Handler
}
type RegexpHandler struct {
	fileServer    http.Handler
	routes        []*route
	chainsBackup  []*MutationChain
	onRuleMatches []ScanEventHandleFunc
	onPocMatches  []ScanEventHandleFunc
}

func (h *RegexpHandler) HandleRule(rule *MutationRule) {
	h.routes = append(h.routes, &route{
		rule:    rule,
		handler: rule.HTTPHandler(),
	})
}

func (h *RegexpHandler) SetStaticDir(path string) {
	h.fileServer = http.FileServer(http.Dir(path))
}

type pocInfo struct {
	Name string
	URI  []string
}

//go:embed assets/html
var indexFileFS embed.FS
var indexTemplate = template.Must(template.ParseFS(indexFileFS, "assets/html/*.gohtml"))

func (h *RegexpHandler) handleIndex(w http.ResponseWriter, r *http.Request) {
	var data []*pocInfo
	for _, chain := range h.chainsBackup {
		var info pocInfo
		for _, rule := range chain.rules {
			info.URI = append(info.URI, rule.Method+" "+rule.ReplacedURI)
		}
		info.Name = chain.Name
		data = append(data, &info)
	}
	err := indexTemplate.ExecuteTemplate(w, "index.gohtml", data)
	if err != nil {
		w.Write([]byte(err.Error()))
	}
}

func (h *RegexpHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	uri := SortedURI(r.URL)
	golog.Infof("[%s] %s", r.Method, uri)
	var body []byte
	if r.Method != http.MethodGet {
		data, err := ioutil.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "write body error", 500)
			return
		}
		body = data
	}
NextRoute:
	for _, route := range h.routes {
		rule := route.rule
		if rule.Method == r.Method && rule.URI.MatchString(uri) {
			for k, re := range rule.Header {
				values := r.Header.Values(k)
				if len(values) != 1 {
					continue NextRoute
				}
				if !re.MatchString(values[0]) {
					continue NextRoute
				}
			}
			if !rule.Body.Match(body) {
				continue NextRoute
			}
			rule.Chain.Lock()
			h.run(route, body, w, r)
			rule.Chain.Unlock()
			return
		}
	}
	if h.fileServer != nil {
		h.fileServer.ServeHTTP(w, r)
	} else {
		if r.URL.Path == "" || r.URL.Path == "/" {
			h.handleIndex(w, r)
		} else {
			w.WriteHeader(404)
			w.Write([]byte("not found"))
		}
	}
}

func (h *RegexpHandler) run(route *route, body []byte, w http.ResponseWriter, r *http.Request) {
	rule := route.rule
	if rule.Method != http.MethodGet {
		r.Body = ioutil.NopCloser(bytes.NewReader(body))
	}
	var fakeResp RespMetrics
	route.handler.ServeHTTP(&fakeResp, r)

	for k, v := range fakeResp.HeaderMap() {
		w.Header().Set(k, v)
	}
	// todo: can this have a conflict?
	if len(fakeResp.status) != 0 {
		// fix go 302 error:
		// if the response is >300 and <400, the location must in response header
		status := fakeResp.status[0]
		if status > 300 && status < 400 && w.Header().Get("location") == "" {
			w.Header().Set("location", r.URL.Path)
		}
		w.WriteHeader(fakeResp.status[0])
	}
	_, _ = w.Write(fakeResp.body)
	var e *ScanEvent
	getEvent := func() *ScanEvent {
		(&sync.Once{}).Do(func() {
			e = &ScanEvent{
				Response:    &fakeResp,
				PocMatched:  rule.Chain.Name,
				RuleMatched: rule.Name,
			}
			newReq := r.Clone(context.Background())
			if rule.Method != http.MethodGet {
				newReq.Body = ioutil.NopCloser(bytes.NewReader(body))
			}
			e.Request = newReq
		})
		return e
	}
	if len(h.onRuleMatches) != 0 {
		for _, fn := range h.onRuleMatches {
			fn(getEvent())
		}
	}
	if len(h.onPocMatches) != 0 && rule.Chain.IsLast(rule) {
		for _, fn := range h.onPocMatches {
			fn(getEvent())
		}
	}
	return
}

func (h *RegexpHandler) Routes() []string {
	var routes []string
	for _, route := range h.routes {
		r := route.rule.URI.String()
		routes = append(routes, r)
	}
	return routes
}

func (y *Yarx) HTTPHandler() *RegexpHandler {
	handlerRules := y.Rules()
	// It's very important to sort the rules, the more flexible it is, the further back it should be
	// thus will help yarx to find the most suitable route for an incoming request
	sort.Slice(handlerRules, func(i, j int) bool {
		a := handlerRules[i]
		b := handlerRules[j]
		if len(a.Header) != 0 && len(b.Header) == 0 {
			return true
		}
		if len(a.Header) == 0 && len(b.Header) != 0 {
			return false
		}

		aU, err1 := url.ParseRequestURI(a.ReplacedURI)
		bU, err2 := url.ParseRequestURI(b.ReplacedURI)
		if err1 == nil && err2 == nil {
			aPathHasVar := strings.Contains(aU.Path, "---ko--")
			bPathHasVar := strings.Contains(bU.Path, "---ko--")
			if !aPathHasVar && bPathHasVar {
				return true
			}
			if aPathHasVar && !bPathHasVar {
				return false
			}
		}

		aHasVar := strings.Contains(a.URI.String(), "(?P<")
		bHasVar := strings.Contains(b.URI.String(), "(?P<")
		if !aHasVar && bHasVar {
			return true
		}
		if aHasVar && !bHasVar {
			return false
		}

		if a.Body.String() != "" && b.Body.String() == "" {
			return true
		}
		if a.Body.String() == "" && b.Body.String() != "" {
			return false
		}
		aSplashCount := strings.Count(a.URI.String(), "/")
		bSplashCount := strings.Count(b.URI.String(), "/")
		if aSplashCount > bSplashCount {
			return true
		}
		if aSplashCount < bSplashCount {
			return false
		}

		if a.Method != http.MethodGet && b.Method == http.MethodGet {
			return true
		}
		if a.Method == http.MethodGet && b.Method != http.MethodGet {
			return false
		}

		return i < j
	})
	handlerRules = mergeRules(handlerRules)
	handler := &RegexpHandler{}
	handler.chainsBackup = y.Chains()
	for _, rule := range handlerRules {
		handler.HandleRule(rule)
	}
	return handler
}

func handleError(err error, writer http.ResponseWriter) {
	golog.Error(err)
	writer.WriteHeader(500)
	_, _ = writer.Write([]byte(err.Error()))
}

type stringRule struct {
	level  int
	name   string
	uri    string
	method string
	body   string
}

// merge the rules if uri, body, header, method are all same
func mergeRules(rules []*MutationRule) []*MutationRule {
	newRules := append(rules[:0:0], rules...)
	var ruleHelper []*stringRule
	for _, rule := range newRules {
		ruleHelper = append(ruleHelper, &stringRule{
			level:  rule.level,
			name:   rule.Name,
			uri:    rule.URI.String(),
			method: rule.Method,
			body:   rule.Body.String(),
		})
	}

	for i, curRule := range ruleHelper {
		if newRules[i] == nil {
			continue
		}
	NextRule:
		for j := i + 1; j < len(ruleHelper); j++ {
			if newRules[j] == nil {
				continue
			}
			otherRule := ruleHelper[j]
			if curRule.uri == otherRule.uri &&
				curRule.method == otherRule.method &&
				curRule.body == otherRule.body {
				baseRule := newRules[i]
				targetRule := newRules[j]
				// check header collision
				if len(baseRule.Header) != len(targetRule.Header) {
					continue NextRule
				}
				for k, v := range baseRule.Header {
					if targetRule.Header[k] == nil {
						continue NextRule
					}
					if v.String() != targetRule.Header[k].String() {
						continue NextRule
					}
				}

				if baseRule.Status != targetRule.Status {
					golog.Warnf("response status collision of %s and %s", baseRule, targetRule)
					golog.Warnf("deleting %s", targetRule)
					newRules[j] = nil
					continue NextRule
				}
				golog.Infof("trying to merge %s with %s",
					baseRule, targetRule)
				for _, fn := range targetRule.MutateFuncs {
					baseRule.MutateFuncs = append(baseRule.MutateFuncs, fn)
				}
				// todo: how to do this?
				baseRule.Name += "||" + targetRule.Name
				baseRule.Chain.Name += "||" + targetRule.Chain.Name
				newRules[j] = nil
			}
		}
	}
	var finalRules []*MutationRule
	for _, rule := range newRules {
		if rule != nil {
			finalRules = append(finalRules, rule)
		}
	}
	return finalRules
}
