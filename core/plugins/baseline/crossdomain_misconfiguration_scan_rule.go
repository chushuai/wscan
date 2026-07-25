/**
* @Author: shaochuyu
* @Date: 4/12/24
 */

package baseline

import (
	"context"
	"wscan/core/model"
	"wscan/core/plugins/base"
	logger "wscan/core/utils/log"
)

type CrossDomainMisconfigurationScanRule struct {
}

func (*CrossDomainMisconfigurationScanRule) Finger() *base.Finger {
	return &base.Finger{
		CheckAction: func(ctx context.Context, a *base.Apollo) error {
			flow := a.GetTargetFlow()
			corsAllowOriginValue := flow.Response.GetHeader("access-control-allow-origin")
			if corsAllowOriginValue == "*" {
				v := a.NewWebVuln(flow.Request, flow.Response, nil)
				if v != nil {
					v.SetTargetURL(flow.Request.URL())
					v.Payload = ""
					a.OutputVuln(v)
				}
				logger.Infof("Found crossdomain %s ", "baseline/config/crossdomain")
			}
			return nil
		},
		Channel: "web-generic",
		Binding: &model.VulnBinding{ID: "baseline/config/crossdomain", Plugin: "baseline/config/crossdomain", Category: "baseline/cookie/secure", Severity: model.SeverityLow},
	}
}
