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
	"wscan/core/utils/checker"
)

type CookieHttpOnlyScanRule struct {
	filter *checker.URLChecker
}

func (*CookieHttpOnlyScanRule) Finger() *base.Finger {
	return &base.Finger{
		CheckAction: func(ctx context.Context, a *base.Apollo) error {
			flow := a.GetTargetFlow()
			cookies := flow.Response.Cookies()
			for _, cookie := range cookies {
				if !cookie.HttpOnly {
					if http.IsCookieExpired(cookie) {
						continue
					} else {
						v := a.NewWebVuln(flow.Request, flow.Response, nil)
						if v != nil {
							v.SetTargetURL(flow.Request.URL())
							v.Payload = ""
							a.OutputVuln(v)
						}
					}
				}
			}

			return nil
		},
		Channel: "web-generic",
		Binding: &model.VulnBinding{ID: "baseline/cookie/http-only", Plugin: "baseline/cookie/http-only", Category: "baseline/cookie/http-only", Severity: model.SeverityLow},
	}
}
