/**
* @Author: shaochuyu
* @Date: 4/12/24
 */

package baseline

import (
	"context"
	"net/http"
	"strings"
	"wscan/core/model"
	"wscan/core/plugins/base"
	"wscan/core/utils/checker"
	logger "wscan/core/utils/log"
)

type CookieLooselyScopedScanRule struct {
	filter *checker.URLChecker
}

func (*CookieLooselyScopedScanRule) Finger() *base.Finger {
	return &base.Finger{
		CheckAction: func(ctx context.Context, a *base.Apollo) error {
			flow := a.GetTargetFlow()
			hostName := flow.Request.Hostname()
			cookies := flow.Response.Cookies()
			for _, cookie := range cookies {
				if IsLooselyScopedCookie(cookie, hostName) {
					v := a.NewWebVuln(flow.Request, flow.Response, nil)
					if v != nil {
						v.SetTargetURL(flow.Request.URL())
						v.Payload = ""
						a.OutputVuln(v)
					}
					logger.Infof("Found loosely_scoped %s ", "baseline/cookie/loosely_scoped")
				}
			}
			return nil
		},
		Channel: "web-generic",
		Binding: &model.VulnBinding{ID: "baseline/cookie/loosely_scoped", Plugin: "baseline/cookie/loosely_scoped", Category: "baseline/cookie/loosely_scoped", Severity: model.SeverityLow},
	}
}
func (*CookieLooselyScopedScanRule) detect() {

}

func IsLooselyScopedCookie(cookie *http.Cookie, host string) bool {
	cookieDomain := cookie.Domain
	if cookieDomain == "" {
		return false
	}
	cookieDomains := strings.Split(cookieDomain, ".")
	hostDomains := strings.Split(host, ".")

	isFromTheSameDomain := IsCookieAndHostHaveTheSameDomain(cookieDomains, hostDomains)
	if !isFromTheSameDomain {
		return true
	}

	if !strings.HasPrefix(cookieDomain, ".") && len(cookieDomains) >= 2 && !isFromTheSameDomain {
		return cookieDomain != host
	}

	if len(cookieDomains) != 2 {
		cookieDomains = strings.Split(cookieDomain[1:], ".")
	}

	if len(cookieDomains) == 0 || len(cookieDomains) >= len(hostDomains) {
		return false
	}

	for i := 1; i <= len(cookieDomains); i++ {
		if !strings.EqualFold(cookieDomains[len(cookieDomains)-i], hostDomains[len(hostDomains)-i]) {
			return false
		}
	}

	return true

}

func IsCookieAndHostHaveTheSameDomain(cookieDomains, hostDomains []string) bool {
	if len(cookieDomains) < 0 || len(hostDomains) < 0 || (hostDomains[0] == "" && len(hostDomains) == 1) || (cookieDomains[0] == "" && len(hostDomains) == 1) {
		return true
	}

	if !strings.EqualFold(cookieDomains[len(cookieDomains)-1], hostDomains[len(hostDomains)-1]) {
		return false
	}

	if len(cookieDomains) < 2 || len(hostDomains) < 2 || !strings.EqualFold(cookieDomains[len(cookieDomains)-2], hostDomains[len(hostDomains)-2]) {
		return false
	}

	return true
}
