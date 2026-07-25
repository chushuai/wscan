/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package sql_injection

import (
	"context"
	"errors"
	"regexp"
	"wscan/core/model"
	"wscan/core/plugins/base"
	"wscan/core/plugins/sql_injection/sqli_detector"
	logger "wscan/core/utils/log"
)

type Config struct {
	base.PluginBaseConfig        `json:",inline" yaml:",inline"`
	sqli_detector.DetectorConfig `json:",inline" yaml:",inline"`
	DetectSQLiInCookie           bool `json:"detect_sqli_in_cookie" yaml:"detect_sqli_in_cookie" #:"是否检查在 cookie 中的注入"`
}

type SQLInjection struct {
	base.PluginMixinInitConfig
	base.PluginMixinClose
}

type Detector struct {
	Config *DetectorConfig
	Apollo *base.Apollo
}

// http://testphp.vulnweb.com/listproducts.php?cat=extractvalue(1,concat(char(126),md5(0067340924)))
// 2ee9670583f4569f2e0f8eb31d9d0de
type DetectorConfig struct {
	BooleanBasedDetection      bool     `json:"boolean_based_detection" yaml:"boolean_based_detection" #:"是否检测布尔盲注"`
	ErrorBasedDetection        bool     `json:"error_based_detection" yaml:"error_based_detection" #:"是否检测报错注入"`
	TimeBasedDetection         bool     `json:"time_based_detection" yaml:"time_based_detection" #:"是否检测时间盲注"`
	DangerouslyUseCommentInSQL bool     `json:"use_comment_in_payload" yaml:"use_comment_in_payload" #:"在 payload 中使用 or, 慎用！可能导致删库！"`
	Dbms                       []string `json:"-" yaml:"-"`
}

type ErrorRegex struct {
	ID    string
	Dbms  string
	Regex *regexp.Regexp
}

type TimeBasedDetectionStatInfo struct {
	TimeBasedNormalStatInfo `json:"normal,inline"`
	// Steps 记录所有的验证阶梯（例如 2s, 4s, 6s...）
	Steps []DetectionStep `json:"steps"`
}

type DetectionStep struct {
	Sleep   int   `json:"sleep"`   // 预设的时延 (ms)
	Samples []int `json:"samples"` // 实际测得的耗时 (ms)
}

type TimeBasedNormalStatInfo struct {
	Samples   []int   `json:"samples"`
	Avg       float64 `json:"avg"`
	StdDev    float64 `json:"std_dev"`
	SleepTime int     `json:"sleep_time"` // 最终触发漏洞的那个延时
}

func (c *Config) BaseConfig() *base.PluginBaseConfig {
	return &c.PluginBaseConfig
}
func (*SQLInjection) Close() error {
	return nil
}
func (*SQLInjection) DefaultConfig() base.PluginConfigInterface {
	return &Config{PluginBaseConfig: base.PluginBaseConfig{Name: "sqldet", Enabled: true},
		DetectorConfig: sqli_detector.DetectorConfig{BooleanBasedDetection: true,
			ErrorBasedDetection: true, TimeBasedDetection: true,
		}, DetectSQLiInCookie: true}
}

func (p *SQLInjection) Fingers() []*base.Finger {
	fingers := []*base.Finger{}
	fingers = append(fingers, p.sqlErrorFinger())
	fingers = append(fingers, p.sqlBlindFinger())
	fingers = append(fingers, p.booleanFinger())
	fingers = append(fingers, p.sqlCookieFinger())
	return fingers
}
func (p *SQLInjection) GetConfig() base.PluginConfigInterface {
	return p.PluginMixinInitConfig.GetConfig()
}

func (p *SQLInjection) Init(ctx context.Context, pci base.PluginConfigInterface, bb *base.ApolloBase) error {
	logger.Debug("SQLInjection Plugin init")
	return p.PluginMixinInitConfig.Init(ctx, pci, bb)
}
func (sqli *SQLInjection) sqlBlindFinger() *base.Finger {
	return &base.Finger{
		Channel: "web-generic",
		Binding: &model.VulnBinding{ID: "sqldet/blind-based/default", Plugin: "blind-based/default", Category: "sqldet", Severity: model.SeverityHigh},
		CheckAction: func(ctx context.Context, apollo *base.Apollo) error {
			config, ok := sqli.GetConfig().(*Config)
			if !ok {
				return errors.New("invalid plugin config type: expected *Config")
			}
			if !config.TimeBasedDetection {
				return nil
			}
			d := sqli_detector.Detector{
				Apollo: apollo,
				Config: &config.DetectorConfig,
			}
			return d.DetectTimeBased(ctx)
		},
	}
}

func (sqli *SQLInjection) booleanFinger() *base.Finger {
	return &base.Finger{
		Channel: "web-generic",
		Binding: &model.VulnBinding{ID: "sqldet/boolean/default", Plugin: "boolean/default", Category: "sqldet", Severity: model.SeverityHigh},
		CheckAction: func(ctx context.Context, apollo *base.Apollo) error {
			config, ok := sqli.GetConfig().(*Config)
			if !ok {
				return errors.New("invalid plugin config type: expected *Config")
			}
			if !config.BooleanBasedDetection {
				return nil
			}
			d := sqli_detector.Detector{
				Apollo: apollo,
				Config: &config.DetectorConfig,
			}
			return d.DetectBooleanBased(ctx)
		},
	}
}

func (sqli *SQLInjection) sqlCookieFinger() *base.Finger {
	return &base.Finger{
		Channel: "web-generic",
		Binding: &model.VulnBinding{ID: "sqldet/cookie/default", Plugin: "cookie/default", Category: "sqldet", Severity: model.SeverityHigh},
		CheckAction: func(ctx context.Context, apollo *base.Apollo) error {
			config, ok := sqli.GetConfig().(*Config)
			if !ok {
				return errors.New("invalid plugin config type: expected *Config")
			}
			if !config.DetectSQLiInCookie {
				return nil
			}
			d := sqli_detector.Detector{
				Apollo: apollo,
				Config: &config.DetectorConfig,
			}
			flow := d.Apollo.GetTargetFlow()
			return d.DetectErrorBased(ctx, flow.Request.ParamsCookie())
		},
	}
}
func (sqli *SQLInjection) sqlErrorFinger() *base.Finger {
	return &base.Finger{
		Channel: "web-generic",
		Binding: &model.VulnBinding{ID: "sqldet/error-based/default", Plugin: "error-based/default", Category: "sqldet", Severity: model.SeverityHigh},
		CheckAction: func(ctx context.Context, apollo *base.Apollo) error {
			config, ok := sqli.GetConfig().(*Config)
			if !ok {
				return errors.New("invalid plugin config type: expected *Config")
			}
			if !config.ErrorBasedDetection {
				return nil
			}
			d := sqli_detector.Detector{
				Apollo: apollo,
				Config: &config.DetectorConfig,
			}
			flow := d.Apollo.GetTargetFlow()
			return d.DetectErrorBased(ctx, flow.Request.ParamsAll())
		},
	}
}
