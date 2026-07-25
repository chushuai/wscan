/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package xss

import (
	"context"
	"fmt"
	"strings"
	"wscan/core/http"
	"wscan/core/model"
	"wscan/core/plugins/base"
	"wscan/core/utils"
	"wscan/core/utils/checker"
	logger "wscan/core/utils/log"
)

type cookieXSS struct {
	filter *checker.URLChecker
}

func (c *cookieXSS) Finger() *base.Finger {
	return &base.Finger{
		CheckAction: func(ctx context.Context, bi *base.Apollo) error {
			flow := bi.GetTargetFlow()
			if c.filter != nil && !c.filter.IsInserted(flow.Request.URL().String(), false) {
				return nil
			}
			logger.Debugf("Start detection XSS in Cookie, URL=%s", flow.Request.URL().String())

			// 获取原始请求的 Cookie 头
			cookieHeader := flow.Request.Header.Get("Cookie")
			if cookieHeader == "" {
				return nil
			}

			// 解析 Cookie 键值对
			cookies := parseCookieHeader(cookieHeader)
			for _, cookie := range cookies {
				xssPayload := utils.RandomStr(utils.AsciiLowercase, 6)

				// 构造带有 XSS payload 的 Cookie 值
				cloneReq := flow.Request.DeepClone()
				cloneReq.SetHeader("Cookie", replaceCookieValue(cookieHeader, cookie.Key, xssPayload))

				res, err := bi.HTTPClient.Respond(ctx, cloneReq)
				if err != nil {
					continue
				}
				contentType := strings.ToLower(res.GetContentType())
				if !strings.Contains(contentType, "html") {
					continue
				}
				locations := SearchInputInResponse(xssPayload, res.Text)
				if len(locations) == 0 {
					continue
				}
				location := locations[len(locations)-1]
				if location.Type == "html" || location.Type == "attribute" {
					// 生成验证 payload
					flag := utils.RandomStr(utils.AsciiLowercase, 5)
					tagname, _ := location.Details["tagname"].(string)
					if tagname == "" {
						continue
					}
					verifyPayload := fmt.Sprintf("</%s><%s>", tagname, flag)
					cloneReq2 := flow.Request.DeepClone()
					cloneReq2.SetHeader("Cookie", replaceCookieValue(cookieHeader, cookie.Key, verifyPayload))

					verifyRes, err := bi.HTTPClient.Respond(ctx, cloneReq2)
					if err != nil {
						continue
					}
					verifyLocations := SearchInputInResponse(flag, verifyRes.Text)
					for _, loc := range verifyLocations {
						if loc.Details["tagname"] == flag {
							param := &http.Parameter{
								Position: http.PositionCookie,
								Key:      cookie.Key,
								Value:    "<sCrIpT>alert(1)</ScRiPt>",
							}
							v := bi.NewWebVuln(cloneReq, res, param)
							if v != nil {
								v.SetTargetURL(flow.Request.URL())
								v.Payload = "<sCrIpT>alert(1)</ScRiPt>"
								bi.OutputVuln(v)
							}
							return nil
						}
					}
				}
			}
			return nil
		},
		Channel: "web-generic",
		Binding: &model.VulnBinding{
			ID:       "xss/reflected/cookie",
			Plugin:   "xss/reflected",
			Category: "xss",
			Severity: model.SeverityMedium,
		},
	}
}

// cookiePair 表示一个 Cookie 键值对
type cookiePair struct {
	Key   string
	Value string
}

// parseCookieHeader 解析 Cookie 头
func parseCookieHeader(header string) []cookiePair {
	var pairs []cookiePair
	for _, part := range strings.Split(header, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		idx := strings.Index(part, "=")
		if idx < 0 {
			continue
		}
		pairs = append(pairs, cookiePair{
			Key:   part[:idx],
			Value: part[idx+1:],
		})
	}
	return pairs
}

// replaceCookieValue 替换 Cookie 头中指定 key 的值
func replaceCookieValue(header, key, newValue string) string {
	parts := strings.Split(header, ";")
	for i, part := range parts {
		part = strings.TrimSpace(part)
		idx := strings.Index(part, "=")
		if idx < 0 {
			continue
		}
		if part[:idx] == key {
			parts[i] = fmt.Sprintf("%s=%s", key, newValue)
			break
		}
	}
	return strings.Join(parts, "; ")
}
