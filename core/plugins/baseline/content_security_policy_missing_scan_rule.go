/**
* @Author: shaochuyu
* @Date: 4/11/24
 */

package baseline

import (
	"context"
	"golang.org/x/net/html"
	"strings"
	"wscan/core/model"
	"wscan/core/plugins/base"
	"wscan/core/utils"
	logger "wscan/core/utils/log"
)

const (
	CONTENT_SECURITY_POLICY = "content-security-policy"
)

type ContentSecurityPolicyMissingScanRule struct {
}

func FindElements(htmlContent string, data string) ([]*html.Node, error) {
	var metaElements []*html.Node

	// 解析 HTML 文档
	doc, err := html.Parse(strings.NewReader(htmlContent))
	if err != nil {
		return nil, err
	}

	// 遍历 HTML 节点树以找到 meta 元素
	var f func(*html.Node)
	f = func(n *html.Node) {
		if n.Type == html.ElementNode && n.Data == data {
			metaElements = append(metaElements, n)
		}
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			f(c)
		}
	}
	f(doc)

	return metaElements, nil
}

func (*ContentSecurityPolicyMissingScanRule) Finger() *base.Finger {
	return &base.Finger{
		CheckAction: func(ctx context.Context, a *base.Apollo) error {
			flow := a.GetTargetFlow()
			// 检查HTML响应
			if !flow.Response.IsHTML() || utils.IsRedirection(flow.Response.StatusCode) {
				return nil
			}
			metaElements, err := FindElements(flow.Response.Text, "meta")
			if err != nil {
				return nil
			}
			vul := false
			var httpEquiv string
			for _, meta := range metaElements {
				for _, attr := range meta.Attr {
					if attr.Key == "http-equiv" {
						httpEquiv = attr.Val
					}
				}

			}
			if flow.Response.GetHeader(CONTENT_SECURITY_POLICY) == "" && !strings.EqualFold(httpEquiv, CONTENT_SECURITY_POLICY) {
				vul = true
			}
			if flow.Response.GetHeader("X-Content-Security-Policy") != "" || flow.Response.GetHeader("X-WebKit-CSP") != "" {
				vul = true
			}
			if flow.Response.GetHeader("Content-Security-Policy-Report-Only") != "" {
				vul = true
			}
			if vul {
				v := a.NewWebVuln(flow.Request, flow.Response, nil)
				if v != nil {
					v.SetTargetURL(flow.Request.URL())
					v.Payload = ""
					a.OutputVuln(v)
				}
				logger.Infof("Found ContentSecurityPolicyMissingScanRule %s ", "baseline/header/content_security_policy_missing")
			}
			return nil
		},
		Channel: "web-generic",
		Binding: &model.VulnBinding{ID: "baseline/header/content_security_policy_missing", Plugin: "baseline/header/content_security_policy_missing", Category: "baseline/header/content_security_policy_missing", Severity: model.SeverityLow},
	}

}
