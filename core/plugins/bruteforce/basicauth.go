/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package bruteforce

import (
	"context"
	"encoding/base64"
	"fmt"
	"wscan/core/http"
	"wscan/core/model"
	"wscan/core/plugins/base"
	"wscan/core/utils/checker"
	"wscan/core/utils/comparer"
	logger "wscan/core/utils/log"
)

type basicAuth struct {
	website *checker.URLChecker
	bf      *BruteForce
}

// D1-14: 增加 baseline 比对 + 修复 goroutine 泄漏 + 修复 context.TODO()
func (b *basicAuth) Finger() *base.Finger {
	return &base.Finger{
		CheckAction: func(ctx context.Context, a *base.Apollo) error {
			flow := a.GetTargetFlow()
			if flow.Response.GetHeader("Www-Authenticate") == "" {
				return nil
			}
			logger.Debugf("Start detection basicAuth, %s", flow.Request.URL().String())

			// D1-14: 发送已知错误凭证获取 baseline
			wrongCred := base64.StdEncoding.EncodeToString([]byte("wscan_invalid:wscan_invalid"))
			baselineReq, _ := http.NewRequest("GET", flow.Request.URL().String(), nil)
			baselineReq.SetHeader("Authorization", "Basic "+wrongCred)
			baselineRes, _ := a.HTTPClient.Respond(ctx, baselineReq)

			userPassChan, stopChan := b.bf.userPassChan(0, b.bf.usernames, b.bf.passwords)
			// D1-14: 使用 defer close(stopChan) 确保 channel 被关闭，修复 goroutine 泄漏
			defer close(stopChan)

			for userPass := range userPassChan {
				fmt.Println(fmt.Sprintf("%s:%s", userPass[0], userPass[1]))
				base64UsrPwd := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", userPass[0], userPass[1])))
				req, _ := http.NewRequest("GET", flow.Request.URL().String(), nil)
				req.SetHeader("Authorization", `Basic `+base64UsrPwd)
				logger.Info(fmt.Sprintf("%s:%s", userPass[0], userPass[1]), base64UsrPwd)
				// D1-14: 使用 ctx 替代 context.TODO()
				res, err := a.HTTPClient.Respond(ctx, req)
				if err != nil {
					logger.Error(err)
					continue
				}
				if res.StatusCode >= 200 && res.StatusCode < 400 {
					// D1-14: 与 baseline 做差异化比对
					// 如果响应与错误凭证响应非常相似，判定为破解失败
					if baselineRes != nil {
						similarity := comparer.CompareResponse(baselineRes, res)
						if similarity > 0.95 {
							// 响应几乎相同，说明破解未成功
							continue
						}
					}
					v := a.NewWebVuln(req, res, nil)
					if v != nil {
						v.SetTargetURL(flow.Request.URL())
						v.Add("username", userPass[0])
						v.Add("password", userPass[1])
						a.OutputVuln(v)
						return nil
					}
				}
			}
			return nil
		},
		Channel: "web-generic",
		Binding: &model.VulnBinding{ID: "brute-force/basic-auth/default", Plugin: "brute-force/basic-auth/default", Category: "brute-force/basic-auth/default", Severity: model.SeverityMedium},
	}
}
