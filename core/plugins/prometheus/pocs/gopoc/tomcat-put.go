/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package gopoc

import (
	"context"
	"wscan/core/model"
	logger "wscan/core/utils/log"

	"wscan/core/plugins/base"
)

type tomcatPut struct{}

// poc-go-tomcat-put
func (*tomcatPut) Finger() *base.Finger {
	return &base.Finger{
		ExecAction: func(ctx context.Context, ab *base.Apollo) error {
			flow := ab.GetTargetFlow()
			logger.Infof("Start detection [%s] URL=%s", "poc-go-tomcat-put", flow.Request.URL().String())

			return nil
		},
		Channel: "web-directory",
		Binding: &model.VulnBinding{ID: "poc-go-tomcat-put", Plugin: "poc-go-tomcat-put", Category: "poc"},
	}

	return nil
}
