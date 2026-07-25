/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package baseline

import (
	"context"
	"crypto/tls"
	"net"
	"strings"
	"time"
	"wscan/core/model"
	"wscan/core/plugins/base"
	logger "wscan/core/utils/log"
)

type outdatedSSLVersion struct{}

var outdatedVersions = map[uint16]string{
	tls.VersionSSL30: "SSL 3.0",
	tls.VersionTLS10: "TLS 1.0",
	tls.VersionTLS11: "TLS 1.1",
}

func (o *outdatedSSLVersion) Finger() *base.Finger {
	return &base.Finger{
		CheckAction: func(ctx context.Context, a *base.Apollo) error {
			flow := a.GetTargetFlow()
			if flow.Request.URL().Scheme != "https" {
				return nil
			}

			host := flow.Request.URL().Host
			if !strings.Contains(host, ":") {
				host = host + ":443"
			}

			logger.Debugf("Start detecting outdated SSL version, %s", flow.Request.URL().String())

			// 尝试以旧版 TLS 协议连接
			for version, versionName := range outdatedVersions {
				dialer := &net.Dialer{Timeout: 5 * time.Second}
				conn, err := tls.DialWithDialer(
					dialer,
					"tcp", host,
					&tls.Config{
						MinVersion:         version,
						MaxVersion:         version,
						InsecureSkipVerify: true,
					},
				)
				if err != nil {
					continue
				}
				conn.Close()

				// 成功连接说明目标支持旧版 TLS
				v := a.NewWebVuln(flow.Request, flow.Response, nil)
				if v != nil {
					v.SetTargetURL(flow.Request.URL())
					v.Payload = versionName
					a.OutputVuln(v)
				}
			}
			return nil
		},
		Channel: "web-generic",
		Binding: &model.VulnBinding{
			ID:       "baseline/ssl/outdated-version",
			Plugin:   "baseline/ssl/outdated-version",
			Category: "baseline/ssl/outdated-version",
			Severity: model.SeverityMedium,
		},
	}
}
