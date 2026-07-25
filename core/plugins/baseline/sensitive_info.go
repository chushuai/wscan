/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package baseline

import (
	"context"
	"regexp"
	"strings"
	"wscan/core/model"
	"wscan/core/plugins/base"
)

type systemPath struct{}

// 系统路径正则（预编译）
var (
	linuxPathRegex   = regexp.MustCompile(`(?:/usr/local|/home/|/var/log|/etc/|/opt/|/tmp/)[\w/.-]+`)
	windowsPathRegex = regexp.MustCompile(`(?:[A-Za-z]):\\(?:Users|Windows|Program Files|inetpub|wwwroot)[\\/\w .-]+`)
)

func (s *systemPath) Finger() *base.Finger {
	return &base.Finger{
		CheckAction: func(ctx context.Context, a *base.Apollo) error {
			flow := a.GetTargetFlow()
			// 排除非文本类型响应
			if flow.Response.IsJavaScript() || flow.Response.IsCss() || flow.Response.IsImage() {
				return nil
			}
			body := flow.Response.Text
			matches := linuxPathRegex.FindAllString(body, -1)
			matches = append(matches, windowsPathRegex.FindAllString(body, -1)...)
			if len(matches) > 0 {
				v := a.NewWebVuln(flow.Request, flow.Response, nil)
				if v != nil {
					v.SetTargetURL(flow.Request.URL())
					v.Payload = matches[0]
					a.OutputVuln(v)
				}
			}
			return nil
		},
		Channel: "web-generic",
		Binding: &model.VulnBinding{
			ID:       "baseline/sensitive/system-path",
			Plugin:   "baseline/sensitive/system-path",
			Category: "baseline/sensitive/system-path",
			Severity: model.SeverityLow,
		},
	}
}

// 身份证号检测
type chinaIDCardNumber struct{}

// 身份证号正则（18位，含校验位）
var chinaIDCardRegex = regexp.MustCompile(`[1-9]\d{5}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx]`)

// D1-19: 身份证号校验位验证（ISO 7064:1983 MOD 11-2）
// 校验位计算公式：sum(weights[i] * digits[i]) % 11，校验位 = (12 - sum%11) % 11
var idCardWeights = [17]int{7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2}
var idCardCheckCodes = [11]byte{'1', '0', 'X', '9', '8', '7', '6', '5', '4', '3', '2'}

// validateChinaIDCard 校验身份证号的校验位是否正确
func validateChinaIDCard(id string) bool {
	if len(id) != 18 {
		return false
	}
	sum := 0
	for i := 0; i < 17; i++ {
		if id[i] < '0' || id[i] > '9' {
			return false
		}
		sum += int(id[i]-'0') * idCardWeights[i]
	}
	checkCode := idCardCheckCodes[sum%11]
	lastChar := id[17]
	if lastChar == 'x' {
		lastChar = 'X'
	}
	return byte(lastChar) == checkCode
}

func (c *chinaIDCardNumber) Finger() *base.Finger {
	return &base.Finger{
		CheckAction: func(ctx context.Context, a *base.Apollo) error {
			flow := a.GetTargetFlow()
			// 排除非文本类型响应
			if flow.Response.IsJavaScript() || flow.Response.IsCss() || flow.Response.IsImage() {
				return nil
			}
			matches := chinaIDCardRegex.FindAllString(flow.Response.Text, -1)
			if len(matches) > 0 {
				// D1-19: 对匹配结果进行校验位验证
				validMatches := []string{}
				for _, m := range matches {
					if validateChinaIDCard(m) {
						validMatches = append(validMatches, m)
					}
				}
				if len(validMatches) > 0 {
					v := a.NewWebVuln(flow.Request, flow.Response, nil)
					if v != nil {
						v.SetTargetURL(flow.Request.URL())
						v.Payload = "china-id-card-number"
						a.OutputVuln(v)
					}
				}
			}
			return nil
		},
		Channel: "web-generic",
		Binding: &model.VulnBinding{
			ID:       "baseline/sensitive/china-id-card",
			Plugin:   "baseline/sensitive/china-id-card",
			Category: "baseline/sensitive/china-id-card",
			Severity: model.SeverityHigh,
		},
	}
}

// 中国手机号检测
type chinaPhoneNumber struct{}

// 中国手机号正则（1开头，第二位3-9，共11位）
var chinaPhoneRegex = regexp.MustCompile(`(?:(?:\+?86)?\s*)?1[3-9]\d{9}`)

func (c *chinaPhoneNumber) Finger() *base.Finger {
	return &base.Finger{
		CheckAction: func(ctx context.Context, a *base.Apollo) error {
			flow := a.GetTargetFlow()
			// 排除非文本类型响应
			if flow.Response.IsJavaScript() || flow.Response.IsCss() || flow.Response.IsImage() {
				return nil
			}
			matches := chinaPhoneRegex.FindAllString(flow.Response.Text, -1)
			if len(matches) > 0 {
				// 过滤掉明显不是手机号的匹配（如连续数字中的子串）
				validMatches := []string{}
				for _, m := range matches {
					cleaned := strings.ReplaceAll(m, " ", "")
					cleaned = strings.ReplaceAll(cleaned, "+86", "")
					cleaned = strings.ReplaceAll(cleaned, "-", "")
					if len(cleaned) == 11 && strings.HasPrefix(cleaned, "1") {
						validMatches = append(validMatches, cleaned)
					}
				}
				if len(validMatches) > 0 {
					v := a.NewWebVuln(flow.Request, flow.Response, nil)
					if v != nil {
						v.SetTargetURL(flow.Request.URL())
						v.Payload = "china-phone-number"
						a.OutputVuln(v)
					}
				}
			}
			return nil
		},
		Channel: "web-generic",
		Binding: &model.VulnBinding{
			ID:       "baseline/sensitive/china-phone",
			Plugin:   "baseline/sensitive/china-phone",
			Category: "baseline/sensitive/china-phone",
			Severity: model.SeverityMedium,
		},
	}
}

// 银行卡号检测
type chinaBankCard struct{}

// 银行卡号正则（16-19位数字，以62/4x/5x开头，需 Luhn 校验）
var chinaBankCardRegex = regexp.MustCompile(`\b(?:62|4\d|5[1-5])\d{14,17}\b`)

// luhnCheck 执行 Luhn 校验算法
func luhnCheck(cardNumber string) bool {
	sum := 0
	nDigits := len(cardNumber)
	parity := nDigits % 2
	for i := 0; i < nDigits; i++ {
		digit := int(cardNumber[i] - '0')
		if i%2 == parity {
			digit *= 2
			if digit > 9 {
				digit -= 9
			}
		}
		sum += digit
	}
	return sum%10 == 0
}

func (c *chinaBankCard) Finger() *base.Finger {
	return &base.Finger{
		CheckAction: func(ctx context.Context, a *base.Apollo) error {
			flow := a.GetTargetFlow()
			// 排除非文本类型响应
			if flow.Response.IsJavaScript() || flow.Response.IsCss() || flow.Response.IsImage() {
				return nil
			}
			matches := chinaBankCardRegex.FindAllString(flow.Response.Text, -1)
			if len(matches) > 0 {
				// 对匹配结果进行 Luhn 校验
				for _, m := range matches {
					if luhnCheck(m) {
						v := a.NewWebVuln(flow.Request, flow.Response, nil)
						if v != nil {
							v.SetTargetURL(flow.Request.URL())
							v.Payload = "china-bank-card"
							a.OutputVuln(v)
						}
						return nil
					}
				}
			}
			return nil
		},
		Channel: "web-generic",
		Binding: &model.VulnBinding{
			ID:       "baseline/sensitive/china-bank-card",
			Plugin:   "baseline/sensitive/china-bank-card",
			Category: "baseline/sensitive/china-bank-card",
			Severity: model.SeverityHigh,
		},
	}
}
