/**
* @Author: shaochuyu
* @Date: 4/12/24
 */

package baseline

import (
	"context"
	"strings"
	"wscan/core/model"
	"wscan/core/plugins/base"
	"wscan/core/utils/checker"
	logger "wscan/core/utils/log"
)

const (
	HTTP_HEADER_XCSP       = "X-Content-Security-Policy"
	HTTP_HEADER_WEBKIT_CSP = "X-WebKit-CSP"
)

type PolicySeverity string // 表示严重程度
var allowedDirectives = []string{
	"require-trusted-types-for",
	"trusted-types",
}

// PolicyError 表示策略错误
type PolicyError struct {
	Severity       PolicySeverity
	Message        string
	DirectiveIndex int
	ValueIndex     int
}

// PolicyErrorConsumer 是处理策略错误的函数类型
type PolicyErrorConsumer func(severity PolicySeverity, message string, directiveIndex, valueIndex int)

type ContentSecurityPolicyScanRule struct {
	filter *checker.URLChecker
}

func (*ContentSecurityPolicyScanRule) Finger() []*base.Finger {
	fingers := []*base.Finger{}
	fingers = append(fingers, &base.Finger{
		CheckAction: func(ctx context.Context, a *base.Apollo) error {

			flow := a.GetTargetFlow()

			if !flow.Response.IsHTML() {
				return nil
			}

			xcspOptions := flow.Response.GetHeader(HTTP_HEADER_XCSP)
			if xcspOptions != "" {
				v := a.NewWebVuln(flow.Request, flow.Response, nil)
				if v != nil {
					v.SetTargetURL(flow.Request.URL())
					v.Payload = ""
					a.OutputVuln(v)
				}
				logger.Infof("Found xcsp X-Content-Security-Policy %s ", "baseline/csp/xcsp")
			}
			return nil
		},
		Channel: "web-generic",
		Binding: &model.VulnBinding{ID: "baseline/csp/xcsp", Plugin: "baseline/csp/xcsp", Category: "baseline/csp/xcsp", Severity: model.SeverityLow},
	})
	fingers = append(fingers, &base.Finger{
		CheckAction: func(ctx context.Context, a *base.Apollo) error {

			flow := a.GetTargetFlow()

			if !flow.Response.IsHTML() {
				return nil
			}

			xcspOptions := flow.Response.GetHeader(HTTP_HEADER_WEBKIT_CSP)
			if xcspOptions != "" {
				v := a.NewWebVuln(flow.Request, flow.Response, nil)
				if v != nil {
					v.SetTargetURL(flow.Request.URL())
					v.Payload = ""
					a.OutputVuln(v)
				}
				logger.Infof("Found xcsp X-WebKit-CSP %s ", "baseline/csp/xwkcsp")
			}
			return nil
		},
		Channel: "web-generic",
		Binding: &model.VulnBinding{ID: "baseline/csp/xwkcsp", Plugin: "baseline/csp/xwkcsp", Category: "baseline/csp/xwkcsp", Severity: model.SeverityLow},
	})
	fingers = append(fingers, &base.Finger{
		CheckAction: func(ctx context.Context, a *base.Apollo) error {

			flow := a.GetTargetFlow()
			if !flow.Response.IsHTML() {
				return nil
			}
			cspHeaderFound := false
			cspOptions := flow.Response.Header[CONTENT_SECURITY_POLICY]
			if len(cspOptions) > 0 {
				cspHeaderFound = true
			}

			if cspHeaderFound {
				var observedErrors []PolicyError
				_ = func(severity PolicySeverity, message string, directiveIndex, valueIndex int) {
					for _, directive := range allowedDirectives {
						if strings.Contains(message, directive) {
							return
						}
					}
					// 添加到观察到的错误列表中
					observedErrors = append(observedErrors, PolicyError{
						Severity:       severity,
						Message:        message,
						DirectiveIndex: directiveIndex,
						ValueIndex:     valueIndex,
					})
				}
				for _, csp := range cspOptions {
					policy := ParsePolicy(csp)
					if len(policy) <= 0 {
						continue
					}
					if len(observedErrors) < 0 {
						// 需要优化，Java代码处理涉及到文案的对比
						v := a.NewWebVuln(flow.Request, flow.Response, nil)
						if v != nil {
							v.SetTargetURL(flow.Request.URL())
							v.Payload = ""
							a.OutputVuln(v)
						}
						logger.Infof("Found csp notices %s ", "baseline/csp/notices")
					}
				}

			}
			return nil
		},
		Channel: "web-generic",
		Binding: &model.VulnBinding{ID: "baseline/csp/notices", Plugin: "baseline/csp/notices", Category: "baseline/csp/notices", Severity: model.SeverityLow},
	})
	fingers = append(fingers, &base.Finger{
		CheckAction: func(ctx context.Context, a *base.Apollo) error {

			flow := a.GetTargetFlow()

			if !flow.Response.IsHTML() {
				return nil
			}
			cspHeaderFound := false
			cspOptions := flow.Response.Header[CONTENT_SECURITY_POLICY]
			if len(cspOptions) > 0 {
				cspHeaderFound = true
			}

			if cspHeaderFound {
				for _, csp := range cspOptions {
					allowedWildcardSources := getAllowedWildcardSources(csp)
					if len(allowedWildcardSources) > 0 {
						v := a.NewWebVuln(flow.Request, flow.Response, nil)
						if v != nil {
							v.SetTargetURL(flow.Request.URL())
							v.Payload = ""
							a.OutputVuln(v)
						}
						logger.Infof("Found csp wildcard %s ", "baseline/csp/wildcard")
					}
				}

			}
			return nil
		},
		Channel: "web-generic",
		Binding: &model.VulnBinding{ID: "baseline/csp/wildcard", Plugin: "baseline/csp/wildcard", Category: "baseline/csp/wildcard", Severity: model.SeverityLow},
	})
	fingers = append(fingers, &base.Finger{
		CheckAction: func(ctx context.Context, a *base.Apollo) error {

			flow := a.GetTargetFlow()

			if !flow.Response.IsHTML() {
				return nil
			}
			cspHeaderFound := false
			cspOptions := flow.Response.Header[CONTENT_SECURITY_POLICY]
			if len(cspOptions) > 0 {
				cspHeaderFound = true
			}

			if cspHeaderFound {
				for _, csp := range cspOptions {
					policy := ParsePolicy(csp)
					if len(policy) <= 0 {
						continue
					}
					for directive, sources := range policy {
						if directive == "script-src" {
							for _, src := range sources {
								if src == "'unsafe-inline'" {
									v := a.NewWebVuln(flow.Request, flow.Response, nil)
									if v != nil {
										v.SetTargetURL(flow.Request.URL())
										v.Payload = ""
										a.OutputVuln(v)
									}
									logger.Infof("Found csp scriptsrc unsafe %s ", "baseline/csp/scriptsrc_unsafe")
								}
							}
						}
					}
				}

			}
			return nil
		},
		Channel: "web-generic",
		Binding: &model.VulnBinding{ID: "baseline/csp/scriptsrc_unsafe", Plugin: "baseline/csp/scriptsrc_unsafe", Category: "baseline/csp/scriptsrc_unsafe", Severity: model.SeverityLow},
	})
	fingers = append(fingers, &base.Finger{
		CheckAction: func(ctx context.Context, a *base.Apollo) error {

			flow := a.GetTargetFlow()

			if !flow.Response.IsHTML() {
				return nil
			}
			cspHeaderFound := false
			cspOptions := flow.Response.Header[CONTENT_SECURITY_POLICY]
			if len(cspOptions) > 0 {
				cspHeaderFound = true
			}

			if cspHeaderFound {
				for _, csp := range cspOptions {
					policy := ParsePolicy(csp)
					if len(policy) <= 0 {
						continue
					}
					for directive, sources := range policy {
						if directive == "script-src" {
							for _, src := range sources {
								if src == "'unsafe-hashes'" {
									v := a.NewWebVuln(flow.Request, flow.Response, nil)
									if v != nil {
										v.SetTargetURL(flow.Request.URL())
										v.Payload = ""
										a.OutputVuln(v)
									}
									logger.Infof("Found csp scriptsrc unsafe hashes %s ", "baseline/csp/scriptsrc_unsafe_hashes")
								}
							}
						}
					}
				}

			}
			return nil
		},
		Channel: "web-generic",
		Binding: &model.VulnBinding{ID: "baseline/csp/scriptsrc_unsafe_hashes", Plugin: "baseline/csp/scriptsrc_unsafe_hashes", Category: "baseline/csp/scriptsrc_unsafe_hashes", Severity: model.SeverityLow},
	})
	fingers = append(fingers, &base.Finger{
		CheckAction: func(ctx context.Context, a *base.Apollo) error {

			flow := a.GetTargetFlow()

			if !flow.Response.IsHTML() {
				return nil
			}
			cspHeaderFound := false
			cspOptions := flow.Response.Header[CONTENT_SECURITY_POLICY]
			if len(cspOptions) > 0 {
				cspHeaderFound = true
			}

			if cspHeaderFound {
				for _, csp := range cspOptions {
					policy := ParsePolicy(csp)
					if len(policy) <= 0 {
						continue
					}
					for directive, sources := range policy {
						if directive == "script-src" {
							for _, src := range sources {
								if src == "'unsafe-eval'" {
									v := a.NewWebVuln(flow.Request, flow.Response, nil)
									if v != nil {
										v.SetTargetURL(flow.Request.URL())
										v.Payload = ""
										a.OutputVuln(v)
									}
									logger.Infof("Found csp scriptsrc unsafe eval %s ", "baseline/csp/scriptsrc_unsafe_eval")
								}
							}
						}
					}
				}

			}
			return nil
		},
		Channel: "web-generic",
		Binding: &model.VulnBinding{ID: "baseline/csp/scriptsrc_unsafe_eval", Plugin: "baseline/csp/scriptsrc_unsafe_eval", Category: "baseline/csp/scriptsrc_unsafe_eval", Severity: model.SeverityLow},
	})
	fingers = append(fingers, &base.Finger{
		CheckAction: func(ctx context.Context, a *base.Apollo) error {

			flow := a.GetTargetFlow()

			if !flow.Response.IsHTML() {
				return nil
			}
			cspHeaderFound := false
			cspOptions := flow.Response.Header[CONTENT_SECURITY_POLICY]
			if len(cspOptions) > 0 {
				cspHeaderFound = true
			}

			if cspHeaderFound {
				for _, csp := range cspOptions {
					policy := ParsePolicy(csp)
					if len(policy) <= 0 {
						continue
					}
					for directive, sources := range policy {
						if directive == "styles-src" {
							for _, src := range sources {
								if src == "'unsafe-hashes'" {
									v := a.NewWebVuln(flow.Request, flow.Response, nil)
									if v != nil {
										v.SetTargetURL(flow.Request.URL())
										v.Payload = ""
										a.OutputVuln(v)
									}
									logger.Infof("Found csp stylesrc unsafe-hashes %s ", "baseline/csp/stylesrc_unsafe_hashes")
								}
							}
						}
					}
				}

			}
			return nil
		},
		Channel: "web-generic",
		Binding: &model.VulnBinding{ID: "baseline/csp/stylesrc_unsafe_hashes", Plugin: "baseline/csp/stylesrc_unsafe_hashes", Category: "baseline/csp/stylesrc_unsafe_hashes", Severity: model.SeverityLow},
	})
	fingers = append(fingers, &base.Finger{
		CheckAction: func(ctx context.Context, a *base.Apollo) error {

			flow := a.GetTargetFlow()

			if !flow.Response.IsHTML() {
				return nil
			}
			cspHeaderFound := false
			cspOptions := flow.Response.Header[CONTENT_SECURITY_POLICY]
			if len(cspOptions) > 0 {
				cspHeaderFound = true
			}

			if cspHeaderFound {
				for _, csp := range cspOptions {
					policy := ParsePolicy(csp)
					if len(policy) <= 0 {
						continue
					}
					for directive, sources := range policy {
						if directive == "styles-src" {
							for _, src := range sources {
								if src == "'unsafe-inline'" {
									v := a.NewWebVuln(flow.Request, flow.Response, nil)
									if v != nil {
										v.SetTargetURL(flow.Request.URL())
										v.Payload = ""
										a.OutputVuln(v)
									}
									logger.Infof("Found csp stylesrc unsafe-inline %s ", "baseline/csp/stylesrc_unsafe_inline")
								}
							}
						}
					}
				}

			}
			return nil
		},
		Channel: "web-generic",
		Binding: &model.VulnBinding{ID: "baseline/csp/stylesrc_unsafe_inline", Plugin: "baseline/csp/stylesrc_unsafe_inline", Category: "baseline/csp/stylesrc_unsafe_inline", Severity: model.SeverityLow},
	})
	fingers = append(fingers, &base.Finger{
		CheckAction: func(ctx context.Context, a *base.Apollo) error {

			flow := a.GetTargetFlow()

			if !flow.Response.IsHTML() {
				return nil
			}
			cspHeaderFound := false
			cspOptions := flow.Response.Header[CONTENT_SECURITY_POLICY]
			if len(cspOptions) > 0 {
				cspHeaderFound = true
			}
			metaElements, err := FindElements(flow.Response.Text, "meta")
			if err != nil {
				return nil
			}
			var httpEquiv string
			for _, meta := range metaElements {
				for _, attr := range meta.Attr {
					if attr.Key == "http-equiv" {
						httpEquiv = attr.Val
					}
				}
			}
			if strings.EqualFold(httpEquiv, CONTENT_SECURITY_POLICY) && cspHeaderFound {
				v := a.NewWebVuln(flow.Request, flow.Response, nil)
				if v != nil {
					v.SetTargetURL(flow.Request.URL())
					v.Payload = ""
					a.OutputVuln(v)
				}
				logger.Infof("Found csp both %s ", "baseline/csp/both")
			}

			return nil
		},
		Channel: "web-generic",
		Binding: &model.VulnBinding{ID: "baseline/csp/both", Plugin: "baseline/csp/both", Category: "baseline/csp/both", Severity: model.SeverityLow},
	})
	fingers = append(fingers, &base.Finger{
		CheckAction: func(ctx context.Context, a *base.Apollo) error {

			flow := a.GetTargetFlow()
			if !flow.Response.IsHTML() {
				return nil
			}
			cspHeaderFound := false
			cspOptions := flow.Response.Header[CONTENT_SECURITY_POLICY]
			if len(cspOptions) > 0 {
				cspHeaderFound = true
			}
			vul := false
			if cspHeaderFound {
				for _, csp := range cspOptions {
					policy := ParsePolicy(csp)
					if len(policy) <= 0 {
						continue
					}
					if !isASCII(csp) {
						vul = true
					}
				}
			}
			if vul {
				v := a.NewWebVuln(flow.Request, flow.Response, nil)
				if v != nil {
					v.SetTargetURL(flow.Request.URL())
					v.Payload = ""
					a.OutputVuln(v)
				}
				logger.Infof("Found csp malformed %s ", "baseline/csp/malformed")
			}

			return nil
		},
		Channel: "web-generic",
		Binding: &model.VulnBinding{ID: "baseline/csp/malformed", Plugin: "baseline/csp/malformed", Category: "baseline/csp/malformed", Severity: model.SeverityLow},
	})
	fingers = append(fingers, &base.Finger{
		CheckAction: func(ctx context.Context, a *base.Apollo) error {
			flow := a.GetTargetFlow()
			if !flow.Response.IsHTML() {
				return nil
			}
			cspHeaderFound := false
			cspOptions := flow.Response.Header[CONTENT_SECURITY_POLICY]
			if len(cspOptions) > 0 {
				cspHeaderFound = true
			}
			vul := false
			if cspHeaderFound {
				for _, csp := range cspOptions {
					policy := ParsePolicy(csp)
					if len(policy) <= 0 {
						continue
					}
					for directive := range policy {
						if directive == "sandbox" || directive == "frame-ancestors" {
							vul = true
						}
					}
				}
			}
			if vul {
				v := a.NewWebVuln(flow.Request, flow.Response, nil)
				if v != nil {
					v.SetTargetURL(flow.Request.URL())
					v.Payload = ""
					a.OutputVuln(v)
				}
				logger.Infof("Found csp meta_bad_directive %s ", "baseline/csp/meta_bad_directive")
			}

			return nil
		},
		Channel: "web-generic",
		Binding: &model.VulnBinding{ID: "baseline/csp/meta_bad_directive", Plugin: "baseline/csp/meta_bad_directive", Category: "baseline/csp/meta_bad_directive", Severity: model.SeverityLow},
	})
	return fingers
}

// Policy 结构体表示 CSP 策略
type Policy struct {
	Directives map[string]string
}

func isASCII(s string) bool {
	for _, c := range s {
		if c > 127 {
			return false
		}
	}
	return true
}

func ParsePolicy(csp string) map[string][]string {
	// 解析csp字符串
	directives := make(map[string][]string)
	if csp == "" {
		return directives
	}
	parts := strings.Split(csp, ";")

	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		subParts := strings.SplitN(part, " ", 2)
		if len(subParts) == 2 {
			directives[subParts[0]] = strings.Fields(subParts[1])
		}
	}

	return directives
}

func getAllowedWildcardSources(csp string) []string {
	policy := ParsePolicy(csp)
	var allowedSources []string
	for directive := range policy {
		if directive == "script-src" {
			allowedSources = append(allowedSources, "script-src")
		}
		if directive == "style-src" {
			allowedSources = append(allowedSources, "style-src")
		}
		if directive == "img-src" {
			allowedSources = append(allowedSources, "img-src")
		}
		if directive == "connect-src" {
			allowedSources = append(allowedSources, "connect-src")
		}
		if directive == "frame-src" {
			allowedSources = append(allowedSources, "frame-src")
		}
		if directive == "frame-ancestors" {
			allowedSources = append(allowedSources, "frame-ancestors")
		}
		if directive == "font-src" {
			allowedSources = append(allowedSources, "font-src")
		}
		if directive == "media-src" {
			allowedSources = append(allowedSources, "media-src")
		}
		if directive == "object-src" {
			allowedSources = append(allowedSources, "object-src")
		}
		if directive == "manifest-src" {
			allowedSources = append(allowedSources, "manifest-src")
		}
		if directive == "worker-src" {
			allowedSources = append(allowedSources, "worker-src")
		}
		if directive == "prefetch-src" {
			allowedSources = append(allowedSources, "prefetch-src")
		}
		if directive == "form-action" {
			allowedSources = append(allowedSources, "form-action")
		}

	}
	return allowedSources
}
