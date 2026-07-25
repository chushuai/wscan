/**
* @Author: shaochuyu
* @Date: 6/16/2026 10:00
 */
package elinject

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

type ELInject struct {
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
func (*ELInject) Close() error {
	return nil
}

// DefaultConfig 返回默认配置, 需要填写插件的默认配置
func (*ELInject) DefaultConfig() base.PluginConfigInterface {
	config := &Config{PluginBaseConfig: base.PluginBaseConfig{
		Name:    "el-injection",
		Enabled: true,
	}}
	return config
}

// Fingers 返回漏洞检测配置
func (p *ELInject) Fingers() []*base.Finger {
	fingers := []*base.Finger{}
	fingers = append(fingers, &base.Finger{
		CheckAction: p.checkAction,
		ExecAction:  p.execAction,
		Channel:     "web-generic",
		Binding:     &model.VulnBinding{ID: "el_injection", Plugin: "el-injection", Category: "el-injection", Severity: model.SeverityCritical},
	})
	return fingers
}

// GetConfig 获取配置
func (p *ELInject) GetConfig() base.PluginConfigInterface {
	return p.PluginMixinInitConfig.GetConfig()
}

// Init 插件初始化
func (p *ELInject) Init(ctx context.Context, pci base.PluginConfigInterface, ab *base.ApolloBase) error {
	logger.Debug("ELInject init")
	return p.PluginMixinInitConfig.Init(ctx, pci, ab)
}

// checkAction 检查参数是否存在且非空
func (p *ELInject) checkAction(ctx context.Context, ab *base.Apollo) error {
	flow := ab.GetTargetFlow()
	for _, param := range flow.Request.ParamsAll() {
		if param.Value != "" {
			return nil
		}
	}
	return fmt.Errorf("no parameters with values found")
}

// ELPayload 表示一个 EL 注入测试 payload
type ELPayload struct {
	Payload      string // 注入 payload 字符串
	VerifyResult string // 期望在响应中出现的验证结果
}

// genELInjectionPayloads 生成 EL 注入测试 payload（三步确认法）
// 参考 AWVS Expression_Language_Injection.script
func genELInjectionPayloads() (addPayloads []ELPayload, subPayloads []ELPayload, antiFP ELPayload) {
	// 生成两个大随机数（9999000-9999999范围，与 AWVS 一致）
	num1 := utils.RandInt(9999000, 9999999)
	num2 := utils.RandInt(9999000, 9999999)

	addResult := num1 + num2
	subResult := num1 - num2

	// 加法测试 payload: ${num1+num2} 和 #{num1+num2}
	addPayloads = []ELPayload{
		{Payload: fmt.Sprintf("${%d+%d}", num1, num2), VerifyResult: fmt.Sprintf("%d", addResult)},
		{Payload: fmt.Sprintf("#{%d+%d}", num1, num2), VerifyResult: fmt.Sprintf("%d", addResult)},
	}

	// 减法测试 payload: ${num1-num2} 和 #{num1-num2}
	// 使用不同范围的 num2 以提高可靠性
	subNum2 := utils.RandInt(10000, 11500)
	subResult = num1 - subNum2
	subPayloads = []ELPayload{
		{Payload: fmt.Sprintf("${%d-%d}", num1, subNum2), VerifyResult: fmt.Sprintf("%d", subResult)},
		{Payload: fmt.Sprintf("#{%d-%d}", num1, subNum2), VerifyResult: fmt.Sprintf("%d", subResult)},
	}

	// 反误报 payload: ${0+0} 和 #{0+0}
	// 期望结果是 "0"，如果响应中出现的 subResult 与 ${0+0} 的结果相同，则为误报
	antiFP = ELPayload{
		Payload:      "${0+0}",
		VerifyResult: fmt.Sprintf("%d", subResult),
	}

	return
}

// testInjection 发送 payload 并检查响应中是否包含验证结果
func testInjection(ctx context.Context, ab *base.Apollo, req *http.Request, param *http.Parameter, payload ELPayload) (bool, *http.Request, *http.Response) {
	parameter := http.Parameter{
		Position: param.Position,
		Key:      param.Key,
		Value:    payload.Payload,
	}
	mutatedReq := req.Mutate(&parameter)
	res, err := ab.HTTPClient.Respond(ctx, mutatedReq)
	if err != nil {
		logger.Error(err)
		return false, nil, nil
	}
	// 仅在 2xx/3xx 响应中检查结果
	if res.StatusCode < 200 || res.StatusCode >= 400 {
		return false, nil, nil
	}
	if strings.Contains(res.Text, payload.VerifyResult) {
		return true, mutatedReq, res
	}
	return false, nil, nil
}

// testInjectionAntiFP 反误报测试：发送 ${0+0}，如果响应中也包含减法结果则为误报
func testInjectionAntiFP(ctx context.Context, ab *base.Apollo, req *http.Request, param *http.Parameter, antiFP ELPayload) bool {
	parameter := http.Parameter{
		Position: param.Position,
		Key:      param.Key,
		Value:    antiFP.Payload,
	}
	mutatedReq := req.Mutate(&parameter)
	res, err := ab.HTTPClient.Respond(ctx, mutatedReq)
	if err != nil {
		logger.Error(err)
		return false
	}
	// 如果 ${0+0} 的响应中也包含减法结果，说明验证结果的出现不是因为表达式计算
	if strings.Contains(res.Text, antiFP.VerifyResult) {
		return true
	}
	return false
}

// execAction 执行 EL 注入漏洞检测（三步确认法）
func (p *ELInject) execAction(ctx context.Context, ab *base.Apollo) error {
	flow := ab.GetTargetFlow()
	logger.Debugf("Start detecting ELInjection vulnerability URL=%s", flow.Request.URL().String())

	for _, param := range flow.Request.ParamsAll() {
		if strings.ToLower(param.Key) == "submit" {
			continue
		}
		if param.Value == "" {
			continue
		}

		// 生成 payload
		addPayloads, subPayloads, antiFP := genELInjectionPayloads()

		// 对每种 EL 语法前缀分别测试
		for i := range addPayloads {
			// 步骤1: 加法测试 ${num1+num2}
			addOK, addReq, addRes := testInjection(ctx, ab, flow.Request, &param, addPayloads[i])
			if !addOK {
				continue
			}

			// 步骤2: 减法测试 ${num1-num2}
			subOK, subReq, subRes := testInjection(ctx, ab, flow.Request, &param, subPayloads[i])
			if !subOK {
				continue
			}

			// 步骤3: 反误报测试 - 发送 ${0+0}，确认其不产生与减法相同的结果
			if testInjectionAntiFP(ctx, ab, flow.Request, &param, antiFP) {
				continue
			}

			// 再次确认减法结果
			subOK2, _, _ := testInjection(ctx, ab, flow.Request, &param, subPayloads[i])
			if !subOK2 {
				continue
			}

			// 检查 baseline - 验证结果不应在原始响应中出现
			baselineReq := flow.Request.DeepClone()
			baselineRes, baselineErr := ab.HTTPClient.Respond(ctx, baselineReq)
			if baselineErr == nil && baselineRes != nil && strings.Contains(baselineRes.Text, subPayloads[i].VerifyResult) {
				continue
			}

			// 报告漏洞
			v := ab.NewWebVuln(subReq, subRes, &http.Parameter{
				Position: param.Position,
				Key:      param.Key,
				Value:    subPayloads[i].Payload,
			})
			if v != nil {
				v.SetTargetURL(flow.Request.URL())
				v.Payload = subPayloads[i].Payload
				ab.OutputVuln(v)
				break
			}

			// 使用加法请求/响应作为备选（当减法结果可能因为其他原因未命中时）
			_ = addReq
			_ = addRes
		}
	}

	return nil
}
