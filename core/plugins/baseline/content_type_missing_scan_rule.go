/**
* @Author: shaochuyu
* @Date: 4/12/24
 */

package baseline

import (
	"context"
	"wscan/core/model"
	"wscan/core/plugins/base"
	"wscan/core/utils/checker"
)

type ContentTypeMissingScanRule struct {
	filter *checker.URLChecker
}

func (*ContentTypeMissingScanRule) Finger() *base.Finger {
	return &base.Finger{
		CheckAction: func(ctx context.Context, bi *base.Apollo) error {
			flow := bi.GetTargetFlow()
			vul := false
			if len(flow.Response.GetRawBody()) > 0 {
				contentType := flow.Response.Header["Content-Type"]
				if len(contentType) > 0 {
					for _, contentTypeDirective := range contentType {
						if contentTypeDirective == "" {
							vul = true
						}
					}
				} else {
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
			}

			return nil
		},
		Channel: "web-generic",
		Binding: &model.VulnBinding{ID: "baseline/header/content_type_missing", Plugin: "baseline/header/content_type_missing", Category: "baseline/header/content_type_missing", Severity: model.SeverityInfo},
	}
}
