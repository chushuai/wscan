/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package baseline

import (
	"context"
	_ "embed"
	"gopkg.in/yaml.v2"
	"regexp"
	"strings"
	"wscan/core/model"
	"wscan/core/plugins/base"
	"wscan/core/plugins/sql_injection/sqli_detector"
	"wscan/core/utils/checker"
	logger "wscan/core/utils/log"
)

type serverError struct {
	filter  *checker.URLChecker
	dbError []*sqli_detector.ErrorRegex
}

func (*serverError) Finger() *base.Finger {
	return nil
}
func (*serverError) isServerError() {
}

var patterns Patterns

//go:embed "application_errors.yaml"
var applicationErrorYaml []byte

// 应用程序错误泄漏

type ApplicationErrorScanRule struct {
	filter *checker.URLChecker
}

// 定义与YAML文件结构相对应的Go结构体
type Pattern struct {
	Type    string `yaml:"type"`
	Content string `yaml:"content"`
}

type Patterns struct {
	Version  string    `yaml:"version"`
	Patterns []Pattern `yaml:"Patterns"`
}

func payloadApplicationErrYaml() (Patterns, error) {
	var patterns Patterns

	err := yaml.Unmarshal(applicationErrorYaml, &patterns)
	if err != nil {
		return patterns, err
	}
	return patterns, nil
}

func (p *ApplicationErrorScanRule) Finger() *base.Finger {
	return &base.Finger{
		CheckAction: func(ctx context.Context, a *base.Apollo) error {
			flow := a.GetTargetFlow()
			logger.Debugf("Start detecting application error %s", flow.Request.URL().String())
			statusCode := flow.Response.StatusCode
			if statusCode == 500 {
				return nil
			} else if statusCode != 400 && !flow.Response.IsApplicationWasm() {
				if flow.Response.IsJavaScript() || flow.Response.IsCss() {
					return nil
				}
				for _, pattern := range patterns.Patterns {
					vul := false
					if pattern.Type == "string" {
						if strings.Contains(flow.Response.Text, pattern.Content) {
							vul = true
							break
						}
					} else {
						re := regexp.MustCompile(pattern.Content)
						if re.MatchString(flow.Response.Text) {
							vul = true
							break
						}
					}
					if vul {
						v := a.NewWebVuln(flow.Request, flow.Response, nil)
						if v != nil {
							v.SetTargetURL(flow.Request.URL())
							v.Payload = pattern.Content
							a.OutputVuln(v)
						}
					}
				}
			}
			return nil
		},
		Channel: "web-generic",
		Binding: &model.VulnBinding{ID: "baseline/sensitive/application_error", Plugin: "baseline/sensitive/application_error", Category: "baseline/sensitive/application_error", Severity: model.SeverityLow},
	}
}

func (*ApplicationErrorScanRule) detect() {

}

func init() {
	yamlConfig, err := payloadApplicationErrYaml()
	if err != nil {
		logger.Fatal(err)
	}
	patterns = yamlConfig
}
