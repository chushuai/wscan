/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package baseline

import (
	"context"
	"regexp"
	"wscan/core/plugins/base"
	logger "wscan/core/utils/log"
)

type Baseline struct {
	base.PluginMixinInitConfig
	base.PluginMixinClose
}

type Config struct {
	base.PluginBaseConfig           `json:",inline" yaml:",inline"`
	DetectCORSHeaderConfig          bool `json:"detect_cors_header_config" yaml:"detect_cors_header_config" #:"检查 cors 相关配置"`
	DetectServerErrorPage           bool `json:"detect_server_error_page" yaml:"detect_server_error_page" #:"检查服务器错误信息"`
	DetectSystemPath                bool `json:"detect_system_path_leak" yaml:"detect_system_path_leak" #:"检查响应是否包含系统路径泄露"`
	DetectOutdatedSSLVersion        bool `json:"detect_outdated_ssl_version" yaml:"detect_outdated_ssl_version" #:"检查 ssl 版本问题"`
	DetectHTTPHeaderConfig          bool `json:"detect_http_header_config" yaml:"detect_http_header_config" #:"检查 http 安全相关 header 是否配置"`
	DetectCookieHttpOnly            bool `json:"detect_cookie_httponly" yaml:"detect_cookie_httponly" #:"检查 set-cookie 时是否设置 http only"`
	DetectChinaIDCardNumber         bool `json:"detect_china_id_card_number" yaml:"detect_china_id_card_number" #:"检查响应是否存在身份证号"`
	DetectChinaPhoneNumber          bool `json:"detect_china_phone_number" yaml:"detect_china_phone_number" #:"检查响应是否存在电话号码"`
	DetectChinaBankCard             bool `json:"detect_china_bank_card" yaml:"detect_china_bank_card" #:"检查响应是否存在银行卡号"`
	DetectPrivateIP                 bool `json:"detect_private_ip" yaml:"detect_private_ip" #:"检查响应是否包含内网 ip"`
	DetectEmail                     bool `json:"detect_email" yaml:"detect_email" #:"检查响应是否包含邮箱地址泄露"`
	DetectHTMLComment               bool `json:"detect_html_comment" yaml:"detect_html_comment" #:"检查HTML注释中是否包含敏感信息"`
	DetectHostInjection             bool `json:"detect_host_injection" yaml:"detect_host_injection" #:"检查是否存在Host头注入"`
	DetectSerializationDataInParams bool `json:"detect_serialization_data_in_params" yaml:"detect_serialization_data_in_params" #:"检查参数中是否存在序列化数据"`
	DetectCookiePasswordLeak        bool `json:"detect_cookie_password_leak" yaml:"detect_cookie_password_leak" #:"检查Cookie值中是否包含密码类字符串"`
	DetectChinaAddress              bool `json:"detect_china_address" yaml:"detect_china_address" #:"检查响应是否包含中国地址信息"`
	DetectAutoComplete              bool `json:"detect_auto_complete" yaml:"detect_auto_complete" #:"检查敏感表单字段是否缺少autocomplete=off"`
	DetectUnsafeScheme              bool `json:"detect_unsafe_scheme" yaml:"detect_unsafe_scheme" #:"检查HTTPS页面中是否包含HTTP混合内容"`
	DetectRedirectLogic             bool `json:"detect_redirect_logic" yaml:"detect_redirect_logic" #:"检查是否存在开放重定向漏洞"`
	DetectDebugMode                 bool `json:"detect_debug_mode" yaml:"detect_debug_mode" #:"检查是否开启框架调试模式(Flask/Django/Tornado/Rails等)"`
}

func (c *Config) BaseConfig() *base.PluginBaseConfig {
	return &c.PluginBaseConfig
}

type HeaderPolicy struct {
	Name          string
	Expected      bool
	ExpectedValue *regexp.Regexp
	Scheme        []string
}

// Close 关闭函数
func (*Baseline) Close() error {
	return nil
}

// DefaultConfig 返回默认配置, 需要填写插件的默认配置
func (*Baseline) DefaultConfig() base.PluginConfigInterface {
	config := &Config{PluginBaseConfig: base.PluginBaseConfig{
		Name:       "baseline",
		Enabled:    false,
		IsAdvanced: true,
	},
		DetectCORSHeaderConfig:          true,
		DetectServerErrorPage:           true,
		DetectSystemPath:                true,
		DetectOutdatedSSLVersion:        true,
		DetectHTTPHeaderConfig:          true,
		DetectCookieHttpOnly:            true,
		DetectChinaIDCardNumber:         true,
		DetectChinaPhoneNumber:          true,
		DetectChinaBankCard:             true,
		DetectPrivateIP:                 true,
		DetectEmail:                     true,
		DetectHTMLComment:               true,
		DetectHostInjection:             true,
		DetectSerializationDataInParams: true,
		DetectCookiePasswordLeak:        true,
		DetectChinaAddress:              true,
		DetectAutoComplete:              true,
		DetectUnsafeScheme:              true,
		DetectRedirectLogic:             true,
		DetectDebugMode:                 true,
	}
	return config
}

// Fingers 返回漏洞检测配置
func (p *Baseline) Fingers() []*base.Finger {
	cfg, ok := p.GetConfig().(*Config)
	if !ok || cfg == nil {
		return nil
	}
	fingers := []*base.Finger{}
	if cfg.DetectServerErrorPage {
		fingers = append(fingers, (&ApplicationErrorScanRule{}).Finger())
	}
	if cfg.DetectHTTPHeaderConfig {
		fingers = append(fingers, (&CacheControlScanRule{}).Finger())
		fingers = append(fingers, (&ContentSecurityPolicyMissingScanRule{}).Finger())
		fingers = append(fingers, (&ContentSecurityPolicyScanRule{}).Finger()...)
		fingers = append(fingers, (&ContentTypeMissingScanRule{}).Finger())
	}
	if cfg.DetectCookieHttpOnly {
		fingers = append(fingers, (&CookieHttpOnlyScanRule{}).Finger())
		fingers = append(fingers, (&CookieLooselyScopedScanRule{}).Finger())
		fingers = append(fingers, (&CookieSameSiteScanRule{}).Finger()...)
		fingers = append(fingers, (&CookieSecureFlagScanRule{}).Finger())
	}
	if cfg.DetectCORSHeaderConfig {
		fingers = append(fingers, (&CrossDomainMisconfigurationScanRule{}).Finger())
	}
	if cfg.DetectOutdatedSSLVersion {
		fingers = append(fingers, (&outdatedSSLVersion{}).Finger())
	}
	if cfg.DetectSystemPath {
		fingers = append(fingers, (&systemPath{}).Finger())
	}
	if cfg.DetectChinaIDCardNumber {
		fingers = append(fingers, (&chinaIDCardNumber{}).Finger())
	}
	if cfg.DetectChinaPhoneNumber {
		fingers = append(fingers, (&chinaPhoneNumber{}).Finger())
	}
	if cfg.DetectChinaBankCard {
		fingers = append(fingers, (&chinaBankCard{}).Finger())
	}
	if cfg.DetectPrivateIP {
		fingers = append(fingers, (&privateIPLeak{}).Finger())
	}
	if cfg.DetectEmail {
		fingers = append(fingers, (&emailLeak{}).Finger())
	}
	if cfg.DetectHTMLComment {
		fingers = append(fingers, (&htmlCommentLeak{}).Finger())
	}
	if cfg.DetectHostInjection {
		fingers = append(fingers, (&hostInjection{}).Finger())
	}
	if cfg.DetectSerializationDataInParams {
		fingers = append(fingers, (&serializationDataInParams{}).Finger())
	}
	if cfg.DetectCookiePasswordLeak {
		fingers = append(fingers, (&cookiePasswordLeak{}).Finger())
	}
	if cfg.DetectChinaAddress {
		fingers = append(fingers, (&chinaAddress{}).Finger())
	}
	if cfg.DetectAutoComplete {
		fingers = append(fingers, (&autoCompleteLeak{}).Finger())
	}
	if cfg.DetectUnsafeScheme {
		fingers = append(fingers, (&unsafeSchemeLeak{}).Finger())
	}
	if cfg.DetectRedirectLogic {
		fingers = append(fingers, (&redirectLogic{}).Finger())
	}
	if cfg.DetectDebugMode {
		fingers = append(fingers, (&flaskDebugModeChecker{}).Finger())
		fingers = append(fingers, (&djangoDebugModeChecker{}).Finger())
		fingers = append(fingers, (&pythonTracebackChecker{}).Finger())
		fingers = append(fingers, (&railsDebugModeChecker{}).Finger())
	}
	return fingers
}

// GetConfig 获取配置
func (p *Baseline) GetConfig() base.PluginConfigInterface {
	return p.PluginMixinInitConfig.GetConfig()
}

// Init 插件初始化
func (p *Baseline) Init(ctx context.Context, pci base.PluginConfigInterface, ab *base.ApolloBase) error {
	logger.Debug("Baseline init")
	return p.PluginMixinInitConfig.Init(ctx, pci, ab)
}
