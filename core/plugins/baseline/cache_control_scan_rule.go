/*
*
2 * @Author: shaochuyu
3 * @Date: 4/11/24
*/
package baseline

import (
	"context"
	_ "embed"
	"strings"
	"wscan/core/model"
	"wscan/core/plugins/base"
	"wscan/core/utils"
)

// 重新审查缓存控制指令
type CacheControlScanRule struct {
}

// 缓存控制头未正确设置或缺失，允许浏览器和代理缓存内容。对于CSS、JS或图像文件等静态资源，这可能是预期的，但是应该审查这些资源，以确保不会缓存敏感内容。
func (*CacheControlScanRule) Finger() *base.Finger {
	return &base.Finger{
		CheckAction: func(ctx context.Context, a *base.Apollo) error {
			flow := a.GetTargetFlow()
			// 缺少判断是否是安全链接
			if len(flow.Response.GetRawBody()) > 0 && !flow.Response.IsImage() {
				if utils.IsRedirection(flow.Response.StatusCode) || utils.IsClientError(flow.Response.StatusCode) ||
					utils.IsServerError(flow.Response.StatusCode) || !flow.Response.IsText() ||
					flow.Response.IsJavaScript() || flow.Response.IsCss() {
					// Covers HTML, XML, JSON and TEXT while excluding JS & CSS
					return nil
				}
				cacheControlString := flow.Response.GetHeader("Cache-Control")
				if cacheControlString == "" ||
					strings.Contains(strings.ToLower(cacheControlString), "no-store") ||
					strings.Contains(strings.ToLower(cacheControlString), "no-cache") ||
					strings.Contains(strings.ToLower(cacheControlString), "must-revalidate") {
					v := a.NewWebVuln(flow.Request, flow.Response, nil)
					if v != nil {
						v.SetTargetURL(flow.Request.URL())
						v.Payload = ""
						a.OutputVuln(v)
					}
				}
			}
			return nil
		},
		Channel: "website",
		Binding: &model.VulnBinding{ID: "baseline/cache/control", Plugin: "baseline/cache/control", Category: "baseline/cache/control", Severity: model.SeverityInfo},
	}
}
