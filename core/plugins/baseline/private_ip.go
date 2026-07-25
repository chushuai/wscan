/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package baseline

import (
	"context"
	"regexp"
	"strings"
	"wscan/core/model"
	"wscan/core/plugins/base"
)

type privateIPLeak struct{}

// 私有 IP 正则（预编译）
var privateIPRegex = regexp.MustCompile(
	`\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|` +
		`172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|` +
		`192\.168\.\d{1,3}\.\d{1,3})\b`)

// 需要排除的响应头（这些头中出现私有 IP 是正常的）
var excludeHeaders = []string{
	"X-Forwarded-For",
	"X-Real-Ip",
	"Via",
}

func (p *privateIPLeak) Finger() *base.Finger {
	return &base.Finger{
		CheckAction: func(ctx context.Context, a *base.Apollo) error {
			flow := a.GetTargetFlow()
			// 排除非文本类型响应
			if flow.Response.IsJavaScript() || flow.Response.IsCss() || flow.Response.IsImage() {
				return nil
			}

			// 在响应体中查找私有 IP
			body := flow.Response.Text
			matches := privateIPRegex.FindAllString(body, -1)
			if len(matches) > 0 {
				// 过滤掉常见的非泄露场景
				filteredMatches := []string{}
				for _, m := range matches {
					// 排除 0.0.0.0 和广播地址等特殊 IP
					if strings.HasSuffix(m, ".0") || strings.HasSuffix(m, ".255") {
						continue
					}
					filteredMatches = append(filteredMatches, m)
				}
				if len(filteredMatches) > 0 {
					v := a.NewWebVuln(flow.Request, flow.Response, nil)
					if v != nil {
						v.SetTargetURL(flow.Request.URL())
						v.Payload = filteredMatches[0]
						a.OutputVuln(v)
					}
				}
			}
			return nil
		},
		Channel: "web-generic",
		Binding: &model.VulnBinding{
			ID:       "baseline/sensitive/private-ip",
			Plugin:   "baseline/sensitive/private-ip",
			Category: "baseline/sensitive/private-ip",
			Severity: model.SeverityLow,
		},
	}
}
