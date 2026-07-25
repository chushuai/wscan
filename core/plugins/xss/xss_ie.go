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
	logger "wscan/core/utils/log"
)

type ieFeatureXSS struct{}

// IE-specific XSS payloads
var iePayloads = []struct {
	Description string
	Payload     string
	Type        string // "style", "href", "src"
}{
	// CSS expression() — IE6-9 only
	{Description: "CSS expression injection", Payload: "expression(alert(1))", Type: "style"},
	// VBScript protocol — IE only
	{Description: "vbscript protocol in href", Payload: "vbscript:alert(1)", Type: "href"},
	// JavaScript with IE-specific event
	{Description: "IE event handler", Payload: "javascript:alert(1)//", Type: "href"},
}

func (ie *ieFeatureXSS) Finger() *base.Finger {
	return &base.Finger{
		CheckAction: func(ctx context.Context, bi *base.Apollo) error {
			flow := bi.GetTargetFlow()
			logger.Debugf("Start IE-specific XSS detection, URL=%s", flow.Request.URL().String())

			for _, param := range flow.Request.ParamsAll() {
				// Step 1: Check if parameter is reflected in the response
				xssPayload := utils.RandomStr(utils.AsciiLettersAndDigits, 8)
				req := flow.Request.Mutate(&http.Parameter{Position: param.Position, Key: param.Key, Prefix: "", Value: xssPayload, Suffix: ""})
				res, err := bi.HTTPClient.Respond(ctx, req)
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

				// Step 2: Test IE-specific payloads based on injection context
				for _, iePayload := range iePayloads {
					switch location.Type {
					case "html":
						tagname, _ := location.Details["tagname"].(string)
						if tagname == "style" && iePayload.Type == "style" {
							// CSS expression() injection in style tag
							flag := utils.RandomStr(utils.AsciiLettersAndDigits, 6)
							verifyPayload := fmt.Sprintf("}%s{width:%s}", flag, iePayload.Payload)
							verifyReq := flow.Request.Mutate(&http.Parameter{Position: param.Position, Key: param.Key, Prefix: "", Value: verifyPayload, Suffix: ""})
							verifyRes, err := bi.HTTPClient.Respond(ctx, verifyReq)
							if err != nil {
								continue
							}
							// 使用 AST 分析验证 flag 是否仍在 style 标签内反射，
							// 而非 strings.Contains（后者无法区分 style 上下文和普通文本节点）
							verifyLocs := SearchInputInResponse(flag, verifyRes.Text)
							for _, loc := range verifyLocs {
								if loc.Type == "html" {
									if locTagname, ok := loc.Details["tagname"].(string); ok && locTagname == "style" {
										v := bi.NewWebVuln(req, res, &param)
										if v != nil {
											v.SetTargetURL(flow.Request.URL())
											v.Payload = fmt.Sprintf("}body{width:%s}", iePayload.Payload)
											v.Param = &http.Parameter{Position: param.Position, Key: param.Key, Prefix: "", Value: fmt.Sprintf("}body{width:%s}", iePayload.Payload), Suffix: ""}
											bi.OutputVuln(v)
										}
										return nil
									}
								}
							}
						} else if tagname != "style" && iePayload.Type == "style" {
							// 反射在文本节点中（非 style 标签），属性闭合 payload 无效。
							// 需要先闭合当前标签再注入带 style 属性的新标签，
							// 并通过 SearchInputInResponse 验证 flag 出现在属性上下文中。
							flag := utils.RandomStr(utils.AsciiLettersAndDigits, 6)
							verifyPayload := fmt.Sprintf("</%s><div style=\"width:%s\">%s", tagname, iePayload.Payload, flag)
							verifyReq := flow.Request.Mutate(&http.Parameter{Position: param.Position, Key: param.Key, Prefix: "", Value: verifyPayload, Suffix: ""})
							verifyRes, err := bi.HTTPClient.Respond(ctx, verifyReq)
							if err != nil {
								continue
							}
							// 使用 AST 分析验证 flag 是否在属性上下文中反射，
							// 而非 strings.Contains（后者无法区分文本节点和属性上下文）
							verifyLocs := SearchInputInResponse(flag, verifyRes.Text)
							for _, loc := range verifyLocs {
								if loc.Type == "attribute" {
									v := bi.NewWebVuln(req, res, &param)
									if v != nil {
										v.SetTargetURL(flow.Request.URL())
										v.Payload = fmt.Sprintf("\" style=\"width:%s\" \"", iePayload.Payload)
										v.Param = &http.Parameter{Position: param.Position, Key: param.Key, Prefix: "", Value: v.Payload, Suffix: ""}
										bi.OutputVuln(v)
									}
									return nil
								}
							}
						}

					case "attribute":
						// Check if reflected in href/src/action attribute — test vbscript:
						attrKey := ""
						if attrs, ok := location.Details["attributes"]; ok {
							for k := range attrs.(map[string]string) {
								attrKey = k
								break
							}
						}
						if (attrKey == "href" || attrKey == "src" || attrKey == "action") && iePayload.Type == "href" {
							flag := utils.RandomStr(utils.AsciiLettersAndDigits, 6)
							verifyPayload := fmt.Sprintf("%s/*%s*/", iePayload.Payload, flag)
							verifyReq := flow.Request.Mutate(&http.Parameter{Position: param.Position, Key: param.Key, Prefix: "", Value: verifyPayload, Suffix: ""})
							verifyRes, err := bi.HTTPClient.Respond(ctx, verifyReq)
							if err != nil {
								continue
							}
							locations := SearchInputInResponse(flag, verifyRes.Text)
							for _, loc := range locations {
								if loc.Type == "attribute" {
									if attrs, ok := loc.Details["attributes"]; ok {
										for _, v := range attrs.(map[string]string) {
											if strings.HasPrefix(strings.ToLower(v), "vbscript:") || strings.HasPrefix(strings.ToLower(v), "javascript:") {
												vuln := bi.NewWebVuln(verifyReq, verifyRes, &param)
												if vuln != nil {
													vuln.SetTargetURL(flow.Request.URL())
													vuln.Payload = iePayload.Payload
													vuln.Param = &http.Parameter{Position: param.Position, Key: param.Key, Prefix: "", Value: iePayload.Payload, Suffix: ""}
													bi.OutputVuln(vuln)
												}
												return nil
											}
										}
									}
								}
							}
						}
					}
				}
			}
			return nil
		},
		Channel: "web-generic",
		Binding: &model.VulnBinding{
			ID:       "xss/reflected/ie-feature",
			Plugin:   "xss/reflected",
			Category: "xss",
			Severity: model.SeverityMedium,
		},
	}
}
