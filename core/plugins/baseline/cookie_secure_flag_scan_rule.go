/**
* @Author: shaochuyu
* @Date: 4/12/24
 */

package baseline

import (
	"context"
	"wscan/core/http"
	"wscan/core/model"
	"wscan/core/plugins/base"
)

type CookieSecureFlagScanRule struct {
}

func (*CookieSecureFlagScanRule) Finger() *base.Finger {
	return &base.Finger{
		CheckAction: func(ctx context.Context, bi *base.Apollo) error {
			flow := bi.GetTargetFlow()
			cookies := flow.Response.Cookies()
			for _, cookie := range cookies {
				if !cookie.Secure {
					if http.IsCookieExpired(cookie) {
						continue
					}
					v := bi.NewWebVuln(flow.Request, flow.Response, nil)
					if v != nil {
						v.SetTargetURL(flow.Request.URL())
						v.Payload = ""
						bi.OutputVuln(v)
					}
				}
			}
			return nil
		},
		Channel: "web-generic",
		Binding: &model.VulnBinding{ID: "baseline/cookie/secure", Plugin: "baseline/cookie/secure", Category: "baseline/cookie/secure", Severity: model.SeverityLow},
	}
}
