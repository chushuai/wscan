/**
* @Author: shaochuyu
* @Date: 6/16/2026 10:00
 */
package prototypepollution

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"wscan/core/http"
	"wscan/core/model"
	"wscan/core/plugins/base"
	logger "wscan/core/utils/log"
)

type PrototypePollution struct {
	base.PluginMixinInitConfig
	base.PluginMixinClose
}

type Config struct {
	base.PluginBaseConfig `json:",inline" yaml:",inline"`
}

// BaseConfig 返回基本配置, 固定格式, 无需修改
func (c *Config) BaseConfig() *base.PluginBaseConfig {
	return &c.PluginBaseConfig
}

// Close 关闭函数
func (*PrototypePollution) Close() error {
	return nil
}

// DefaultConfig 返回默认配置, 需要填写插件的默认配置
func (*PrototypePollution) DefaultConfig() base.PluginConfigInterface {
	config := &Config{PluginBaseConfig: base.PluginBaseConfig{
		Name:    "prototype-pollution",
		Enabled: true,
	}}
	return config
}

// Fingers 返回漏洞检测配置
func (p *PrototypePollution) Fingers() []*base.Finger {
	fingers := []*base.Finger{}
	fingers = append(fingers, &base.Finger{
		CheckAction: p.checkAction,
		ExecAction:  p.execAction,
		Channel:     "web-generic",
		Binding:     &model.VulnBinding{ID: "prototype_pollution", Plugin: "prototype-pollution", Category: "prototype-pollution", Severity: model.SeverityHigh},
	})
	return fingers
}

// GetConfig 获取配置
func (p *PrototypePollution) GetConfig() base.PluginConfigInterface {
	return p.PluginMixinInitConfig.GetConfig()
}

// Init 插件初始化
func (p *PrototypePollution) Init(ctx context.Context, pci base.PluginConfigInterface, ab *base.ApolloBase) error {
	logger.Debug("PrototypePollution init")
	return p.PluginMixinInitConfig.Init(ctx, pci, ab)
}

// checkAction 检查参数是否存在
func (p *PrototypePollution) checkAction(ctx context.Context, ab *base.Apollo) error {
	flow := ab.GetTargetFlow()
	if len(flow.Request.ParamsAll()) > 0 {
		return nil
	}
	return fmt.Errorf("no parameters found")
}

// 原型链污染错误消息模式
var (
	// 精确匹配的错误消息
	protoErrMessages = []string{
		"TypeError: Cannot set property '__proto__' of null",
	}

	// 正则匹配的错误消息
	protoErrRegexps = []*regexp.Regexp{
		regexp.MustCompile(`TypeError: Immutable prototype object .*? cannot have their prototype set`),
	}
)

// searchProtoPollutionError 在响应文本中搜索原型链污染错误消息
func searchProtoPollutionError(text string) string {
	// 搜索精确匹配的错误消息
	for _, msg := range protoErrMessages {
		if strings.Contains(text, msg) {
			return msg
		}
	}
	// 搜索正则匹配的错误消息
	for _, re := range protoErrRegexps {
		match := re.FindString(text)
		if match != "" {
			return match
		}
	}
	return ""
}

// sendAndCheck 发送请求并检查响应中的原型链污染错误消息
func sendAndCheck(ctx context.Context, ab *base.Apollo, req *http.Request, param *http.Parameter) (bool, *http.Request, *http.Response, string) {
	res, err := ab.HTTPClient.Respond(ctx, req)
	if err != nil {
		logger.Error(err)
		return false, nil, nil, ""
	}

	matchedText := searchProtoPollutionError(res.Text)
	if matchedText != "" {
		return true, req, res, matchedText
	}
	return false, nil, nil, ""
}

// execAction 执行原型链污染漏洞检测
// 参考 AWVS Prototype_Pollution.script
func (p *PrototypePollution) execAction(ctx context.Context, ab *base.Apollo) error {
	flow := ab.GetTargetFlow()
	logger.Debugf("Start detecting PrototypePollution vulnerability URL=%s", flow.Request.URL().String())

	for _, param := range flow.Request.ParamsAll() {
		inputName := param.Key
		origValue := param.Value

		// 路径1: 参数名是数组形式（含 [ 且以 ] 结尾）
		// 追加 [__proto__] 到参数名，值设为 {"__proto__":{}}
		if strings.Contains(inputName, "[") && strings.HasSuffix(inputName, "]") {
			// 测试1: inputName[__proto__] = {"__proto__":{}}
			protoKey := inputName + "[__proto__]"
			protoValue := `{"__proto__":{}}`
			parameter := http.Parameter{
				Position: param.Position,
				Key:      protoKey,
				Value:    protoValue,
			}
			req := flow.Request.Mutate(&parameter)
			if found, vulnReq, vulnRes, matchedText := sendAndCheck(ctx, ab, req, &parameter); found {
				v := ab.NewWebVuln(vulnReq, vulnRes, &parameter)
				if v != nil {
					v.SetTargetURL(flow.Request.URL())
					v.Payload = protoValue
					v.Param = &parameter
					v.Add("matched_text", matchedText)
					ab.OutputVuln(v)
					return nil
				}
			}

			// 测试2: inputName[__proto__][__proto__][__proto__] = 1
			deepProtoKey := inputName + "[__proto__][__proto__][__proto__]"
			parameter2 := http.Parameter{
				Position: param.Position,
				Key:      deepProtoKey,
				Value:    "1",
			}
			req2 := flow.Request.Mutate(&parameter2)
			if found, vulnReq, vulnRes, matchedText := sendAndCheck(ctx, ab, req2, &parameter2); found {
				v := ab.NewWebVuln(vulnReq, vulnRes, &parameter2)
				if v != nil {
					v.SetTargetURL(flow.Request.URL())
					v.Payload = "1"
					v.Param = &parameter2
					v.Add("matched_text", matchedText)
					ab.OutputVuln(v)
					return nil
				}
			}
		}

		// 路径2: JSON 值（以 { 开头且以 } 结尾）
		// 发送 {"__proto__":{"__proto__":{}}} 作为值
		if strings.HasPrefix(origValue, "{") && strings.HasSuffix(origValue, "}") {
			protoJSONPayload := `{"__proto__":{"__proto__":{}}}`
			parameter := http.Parameter{
				Position: param.Position,
				Key:      param.Key,
				Value:    protoJSONPayload,
			}
			req := flow.Request.Mutate(&parameter)
			if found, vulnReq, vulnRes, matchedText := sendAndCheck(ctx, ab, req, &parameter); found {
				v := ab.NewWebVuln(vulnReq, vulnRes, &parameter)
				if v != nil {
					v.SetTargetURL(flow.Request.URL())
					v.Payload = protoJSONPayload
					v.Param = &parameter
					v.Add("matched_text", matchedText)
					ab.OutputVuln(v)
					return nil
				}
			}
		}
	}

	return nil
}
