/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package bruteforce

import (
	"context"
	"strings"
	"wscan/core/http"
	"wscan/core/model"
	"wscan/core/plugins/base"
	"wscan/core/utils"
	"wscan/core/utils/checker"
	"wscan/core/utils/comparer"
	logger "wscan/core/utils/log"
)

type formBrute struct {
	urlChecker *checker.URLChecker
	bf         *BruteForce
}

// D1-14: 增加 baseline 比对 + 修复 goroutine 泄漏 + 修复控制流问题
func (p *formBrute) Brute(ctx context.Context, a *base.Apollo) error {
	// 判断是否为登录表单
	flow := a.GetTargetFlow()
	if flow.Request.Method != "POST" {
		return nil
	}
	logger.Debugf("Start detection form-brute, %s\n %s", flow.Request.URL().String(), flow.Request.GetRawBody())
	// https://139.144.1.202/login.php 200 OK
	if strings.Contains(flow.Request.URL().Path, "login") {
		logger.Infof("Found login form %s", flow.Request.URL())
	}
	// username=admin&password=password&Login=Login&user_token=041d6b26e80f6f7c30f6aec92c1c0d05
	usrField := ""
	pwdField := ""
	candidateUsrField := ""
	// username=admin&password=password&Login=Login&user_token=397ca16ba22046aaa838eeeb8b01781d
	for _, param := range flow.Request.ParamsBody() {
		if utils.StringIIn(strings.ToLower(param.Key), []string{"username", "user", "usr", "name"}) {
			usrField = param.Key
		}
		if utils.StringIIn(strings.ToLower(param.Key), []string{"password", "pass", "pwd"}) {
			pwdField = param.Key
		}

		if strings.Contains(strings.ToLower(param.Key), "name") {
			candidateUsrField = param.Key
		}
	}
	if usrField == "" {
		usrField = candidateUsrField
	}

	if usrField == "" || pwdField == "" {
		return nil
	}

	// D1-14: 发送已知错误凭证获取 baseline
	baselineReq := flow.Request.DeepClone()
	// 设置明显错误的凭证来获取 baseline 响应
	baselineUsrParam := http.Parameter{Position: http.PositionBody, Key: usrField, Value: "wscan_invalid_user_9x7k2"}
	baselinePwdParam := http.Parameter{Position: http.PositionBody, Key: pwdField, Value: "wscan_invalid_pass_3m5n8"}
	baselineReq = baselineReq.Mutate(&baselineUsrParam).Mutate(&baselinePwdParam)
	baselineRes, _ := a.HTTPClient.Respond(ctx, baselineReq)

	userPassChan, stopChan := p.bf.userPassChan(0, p.bf.usernames, p.bf.passwords)
	// D1-14: 使用 defer close(stopChan) 确保 channel 被关闭，修复 goroutine 泄漏 (BF-FP-4)
	defer close(stopChan)

	for userPass := range userPassChan {
		usrParameter := http.Parameter{Position: http.PositionBody, Key: usrField, Value: userPass[0]}
		pwdParameter := http.Parameter{Position: http.PositionBody, Key: pwdField, Value: userPass[1]}
		req := flow.Request.Mutate(&usrParameter).Mutate(&pwdParameter)
		logger.Infof("form-brute\n %s", string(req.GetRawBody()))
		// D1-14: 使用 ctx 替代 context.TODO()
		res, err := a.HTTPClient.Respond(ctx, req)
		if err != nil {
			logger.Error(err)
			// D1-14: BF-LG-2 修复 - 将 return nil 改为 continue，跳过失败的组合继续尝试
			continue
		}
		if res.StatusCode != 200 {
			continue
		}
		// D1-14: 与 baseline 做差异化比对
		// 如果 200 响应与错误凭证响应非常相似，判定为破解失败
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
			v.AddMap("username", map[string]any{
				"field": usrField,
				"value": userPass[0],
			})
			v.AddMap("password", map[string]any{
				"field": pwdField,
				"value": userPass[1],
			})
			a.OutputVuln(v)
			return nil
		}
	}

	return nil
}
func (p *formBrute) Finger() *base.Finger {
	return &base.Finger{
		CheckAction: p.Brute,
		Channel:     "web-generic",
		Binding:     &model.VulnBinding{ID: "brute-force/form-brute/default", Plugin: "brute-force/form-brute/default", Category: "brute-force/form-brute/default", Severity: model.SeverityMedium},
	}
}

func (p *formBrute) bruteSinglePass() {

}

func (p *formBrute) bruteUserPass() {

}

func (p *formBrute) processPassword(string, string) string {
	return ""
}
