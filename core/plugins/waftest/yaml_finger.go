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
	"wscan/core/plugins/helper/payload/encoder"
	"wscan/core/plugins/helper/payload/placeholder"
	logger "wscan/core/utils/log"
)

// YamlFinger WAF 测试指纹，实现 base.FingerFactory 接口
type YamlFinger struct {
	*YamlScript
	cfg *Config
}

// Run 执行 WAF 测试：对目标 URL 发送编码后的攻击载荷，检测 WAF 是否拦截
// 核心逻辑：
//  1. 对每个 (encoder, placeholder) 组合，构造攻击请求
//  2. 发送请求并检测响应是否被 WAF 拦截
//  3. 若 WAF 未拦截攻击载荷，则报告漏洞（WAF 绕过/缺失）
func (y *YamlFinger) Run(ctx context.Context, ab *base.Apollo) error {
	flow := ab.GetTargetFlow()
	targetURL := flow.Request.URL().String()

	for _, phSpec := range y.Placeholders {
		for _, encName := range y.Encoder {
			// Step 1: 使用编码器对载荷进行编码
			encodedPayload, err := encoder.Apply(encName, y.Payload)
			if err != nil {
				logger.Debugf("Encoder %s apply error: %v", encName, err)
				continue
			}

			// Step 2: 使用占位符构造 HTTP 请求
			stdReq, err := placeholder.Apply(targetURL, encodedPayload, phSpec.Name, phSpec.Config)
			if err != nil {
				logger.Debugf("Placeholder %s apply error: %v", phSpec.Name, err)
				continue
			}

			// Step 3: 将标准 http.Request 转换为 wscan 内部 Request
			wscanReq, err := http.RequestFromNetHttpRequert(stdReq)
			if err != nil {
				logger.Debugf("Convert request error: %v", err)
				continue
			}

			// Step 4: 发送请求
			res, err := ab.HTTPClient.Respond(ctx, wscanReq)
			if err != nil {
				logger.Debugf("Send request error: %v", err)
				continue
			}

			// Step 5: 检测 WAF 拦截/通过状态
			blocked := y.checkBlocking(string(res.DumpHeader()), res.Text, res.StatusCode)
			passed := y.checkPass(string(res.DumpHeader()), res.Text, res.StatusCode)

			// Step 6: 判断 WAF 是否被绕过
			// - 如果 WAF 拦截了攻击载荷 → WAF 正常工作 → 不报告
			// - 如果 WAF 未拦截攻击载荷：
			//   - 且响应匹配通过模式 (passed) → WAF 被绕过/缺失 → 报告漏洞
			//   - 且 NonBlockedAsPassed=true → 视为通过 → 报告漏洞
			//   - 且 NonBlockedAsPassed=false 且未匹配通过模式 → 不确定 → 不报告
			if !blocked && (passed || y.cfg.NonBlockedAsPassed) {
				v := ab.NewWebVuln(wscanReq, res, nil)
				if v != nil {
					v.SetTargetURL(wscanReq.URL())
					ab.OutputVuln(v)
					return nil
				}
			}
		}
	}
	return nil
}

// checkBlocking 检测响应是否被 WAF 拦截
// 通过响应状态码和正则匹配判断请求是否被 WAF 阻止
func (y *YamlFinger) checkBlocking(responseMsgHeader, body string, statusCode int) bool {
	// 优先检查正则匹配
	if y.cfg.BlockRegex != "" {
		response := body
		if responseMsgHeader != "" {
			response = responseMsgHeader + body
		}
		if response != "" {
			if m, err := regexp.MatchString(y.cfg.BlockRegex, response); err == nil && m {
				return true
			}
		}
	}

	// 检查状态码
	for _, code := range y.cfg.BlockStatusCodes {
		if statusCode == code {
			return true
		}
	}

	return false
}

// checkPass 检测响应是否通过（未被 WAF 拦截的正常响应）
// 通过响应状态码和正则匹配判断请求是否正常通过
func (y *YamlFinger) checkPass(responseMsgHeader, body string, statusCode int) bool {
	// 优先检查正则匹配
	if y.cfg.PassRegex != "" {
		response := body
		if responseMsgHeader != "" {
			response = responseMsgHeader + body
		}
		if response != "" {
			if m, err := regexp.MatchString(y.cfg.PassRegex, response); err == nil && m {
				return true
			}
		}
	}

	// 检查状态码
	for _, code := range y.cfg.PassStatusCodes {
		if statusCode == code {
			return true
		}
	}

	return false
}

// Finger 返回 base.Finger，注册到插件系统
func (y *YamlFinger) Finger() *base.Finger {
	return &base.Finger{
		Channel:    y.Channel,
		Binding:    &model.VulnBinding{ID: y.Type, Plugin: y.Type, Category: y.Type, Severity: model.SeverityInfo},
		ExecAction: y.Run,
	}
}
