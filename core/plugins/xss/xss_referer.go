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

type refererXSS struct {
	filter *checker.URLChecker
}

func (r *refererXSS) Finger() *base.Finger {
	return &base.Finger{
		CheckAction: func(ctx context.Context, bi *base.Apollo) error {
			flow := bi.GetTargetFlow()
			logger.Debugf("Start detection XSS in Referer, URL=%s", flow.Request.URL().String())

			xssPayload := utils.RandomStr(utils.AsciiLowercase, 6)
			req := flow.Request.DeepClone()
			req.SetHeader("Referer", xssPayload)

			res, err := bi.HTTPClient.Respond(ctx, req)
			if err != nil {
				return nil
			}
			contentType := strings.ToLower(res.GetContentType())
			if !strings.Contains(contentType, "html") {
				return nil
			}
			locations := SearchInputInResponse(xssPayload, res.Text)
			if len(locations) == 0 {
				return nil
			}

			// 验证逻辑
			location := locations[len(locations)-1]
			if location.Type == "html" || location.Type == "attribute" {
				tagname, _ := location.Details["tagname"].(string)
				if tagname == "" {
					return nil
				}
				flag := utils.RandomStr(utils.AsciiLowercase, 5)
				verifyPayload := fmt.Sprintf("</%s><%s>", tagname, flag)
				verifyReq := flow.Request.DeepClone()
				verifyReq.SetHeader("Referer", verifyPayload)

				verifyRes, err := bi.HTTPClient.Respond(ctx, verifyReq)
				if err != nil {
					return nil
				}
				verifyLocations := SearchInputInResponse(flag, verifyRes.Text)
				for _, loc := range verifyLocations {
					if loc.Details["tagname"] == flag {
						param := &http.Parameter{
							Position: http.PositionHeader,
							Key:      "Referer",
							Value:    "<sCrIpT>alert(1)</ScRiPt>",
						}
						v := bi.NewWebVuln(req, res, param)
						if v != nil {
							v.SetTargetURL(flow.Request.URL())
							v.Payload = "<sCrIpT>alert(1)</ScRiPt>"
							bi.OutputVuln(v)
						}
						return nil
					}
				}
			}
			return nil
		},
		Channel: "web-generic",
		Binding: &model.VulnBinding{
			ID:       "xss/reflected/referer",
			Plugin:   "xss/reflected",
			Category: "xss",
			Severity: model.SeverityMedium,
		},
	}
}
