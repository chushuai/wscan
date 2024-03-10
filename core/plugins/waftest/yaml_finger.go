/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package waftest

import (
	"context"
	"regexp"
	"wscan/core/http"
	"wscan/core/model"
	"wscan/core/plugins/base"
	logger "wscan/core/utils/log"
)

type YamlFinger struct {
	*YamlScript
	init func(context.Context, *base.Apollo)
	cfg  *Config
}

func (y YamlFinger) Run(ctx context.Context, ab *base.Apollo) error {
	flow := ab.GetTargetFlow()
	for _, param := range flow.Request.ParamsQueryAndBody() {
		// http://testphp.vulnweb.com/listproducts.php?cat=extractvalue(1,concat(char(126),md5(1859984743)))
		parameter := http.Parameter{Position: param.Position, Key: param.Key, Value: y.Payload}
		req := flow.Request.Mutate(&parameter)
		res, err := ab.HTTPClient.Respond(context.TODO(), req)
		if err != nil {
			logger.Error(err)
			continue
		}
		var blocked, passed bool

		blocked, err = y.checkBlocking(string(res.DumpHeader()), res.Text, res.StatusCode)
		if err != nil {
			return err
		}
		passed, err = y.checkPass(string(res.DumpHeader()), res.Text, res.StatusCode)
		if err != nil {
			return err
		}
		if blocked == false || (blocked && passed) || (!blocked && !passed) {
			v := ab.NewWebVuln(req, res, &param)
			if v != nil {
				v.SetTargetURL(flow.Request.URL())
				v.Param = &parameter
				ab.OutputVuln(v)
				break
			}
		}
	}
	return nil
}

// checkPass 使用 HTTP 请求方法检查响应状态码或请求体
// 判断请求是否通过的正则表达式。
func (y *YamlFinger) checkPass(responseMsgHeader, body string, statusCode int) (bool, error) {
	if y.cfg.PassRegex != "" {
		response := body
		if responseMsgHeader != "" {
			response = responseMsgHeader + body
		}
		if response != "" {
			m, _ := regexp.MatchString(y.cfg.PassRegex, response)

			return m, nil
		}
	}

	for _, code := range y.cfg.PassStatusCodes {
		if statusCode == code {
			return true, nil
		}
	}

	return false, nil
}

// checkBlocking 使用检查响应状态码或请求体,一个正则表达式，用于确定请求是否已被阻止。
func (y YamlFinger) checkBlocking(responseMsgHeader, body string, statusCode int) (bool, error) {
	if y.cfg.BlockRegex != "" {
		response := body
		if responseMsgHeader != "" {
			response = responseMsgHeader + body
		}

		if response != "" {
			m, _ := regexp.MatchString(y.cfg.BlockRegex, response)

			return m, nil
		}
	}

	for _, code := range y.cfg.BlockStatusCodes {
		if statusCode == code {
			return true, nil
		}
	}

	return false, nil
}

func (y *YamlFinger) Finger() *base.Finger {
	return &base.Finger{
		Channel:    y.Channel,
		Binding:    &model.VulnBinding{ID: y.Type, Plugin: y.Type, Category: y.Type},
		ExecAction: y.Run,
	}
}
