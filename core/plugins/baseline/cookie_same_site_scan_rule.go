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
	logger "wscan/core/utils/log"
)

type CookieSameSiteScanRule struct {
	filter *checker.URLChecker
}

func (*CookieSameSiteScanRule) Finger() []*base.Finger {
	fingers := []*base.Finger{}
	fingers = append(fingers, &base.Finger{
		CheckAction: func(ctx context.Context, a *base.Apollo) error {
			flow := a.GetTargetFlow()
			cookies := flow.Response.Cookies()
			vul := false
			for _, cookie := range cookies {
				if http.IsCookieExpired(cookie) {
					continue
				}
				sameSite := http.CheckSameSite(cookie)
				if sameSite == "" {
					vul = true
				}

			}
			if vul {
				v := a.NewWebVuln(flow.Request, flow.Response, nil)
				if v != nil {
					v.SetTargetURL(flow.Request.URL())
					v.Payload = ""
					a.OutputVuln(v)
				}

			}
			return nil
		},
		Channel: "web-generic",
		Binding: &model.VulnBinding{ID: "baseline/cookie/no_sameSite", Plugin: "baseline/cookie/no_sameSite", Category: "baseline/cookie/no_sameSite", Severity: model.SeverityLow},
	})
	fingers = append(fingers, &base.Finger{
		CheckAction: func(ctx context.Context, a *base.Apollo) error {

			flow := a.GetTargetFlow()
			cookies := flow.Response.Cookies()
			vul := false

			for _, cookie := range cookies {
				if http.IsCookieExpired(cookie) {
					continue
				}
				sameSite := http.CheckSameSite(cookie)
				if sameSite == "NoneMode" {
					vul = true
				}

			}
			if vul {
				v := a.NewWebVuln(flow.Request, flow.Response, nil)
				if v != nil {
					v.SetTargetURL(flow.Request.URL())
					v.Payload = ""
					a.OutputVuln(v)
				}
			}
			return nil
		},
		Channel: "web-generic",
		Binding: &model.VulnBinding{ID: "baseline/cookie/none_sameSite", Plugin: "baseline/cookie/none_sameSite", Category: "baseline/cookie/none_sameSite", Severity: model.SeverityLow},
	})
	fingers = append(fingers, &base.Finger{
		CheckAction: func(ctx context.Context, bi *base.Apollo) error {

			flow := bi.GetTargetFlow()

			cookies := flow.Response.Cookies()
			vul := false

			for _, cookie := range cookies {
				if http.IsCookieExpired(cookie) {
					continue
				}
				sameSite := http.CheckSameSite(cookie)
				if sameSite != "StrictMode" && sameSite != "LaxMode" && sameSite != "NoneMode" {
					vul = true
				}

			}
			if vul {
				v := bi.NewWebVuln(flow.Request, flow.Response, nil)
				if v != nil {
					v.SetTargetURL(flow.Request.URL())
					v.Payload = ""
					bi.OutputVuln(v)
				}
				logger.Infof("Found sameite noneMode %s ", "baseline/cookie/badval_sameSite")
			}
			return nil
		},
		Channel: "web-generic",
		Binding: &model.VulnBinding{ID: "baseline/cookie/badval_sameSite", Plugin: "baseline/cookie/badval_sameSite", Category: "baseline/cookie/badval_sameSite", Severity: model.SeverityLow},
	})
	return fingers
}
