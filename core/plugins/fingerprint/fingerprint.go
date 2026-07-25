/**
2 * @Author: shaochuyu
3 * @Date: 4/4/24
4 */

package fingerprint

import (
	"context"
	"embed"
	"gopkg.in/yaml.v3"
	"time"
	"wscan/core/http"
	"wscan/core/model"
	"wscan/core/plugins/base"
	"wscan/core/plugins/helper"
	"wscan/core/resource"
	logger "wscan/core/utils/log"
)

type FingerprintInfo struct {
	Name   string `yaml:"name"`
	Author string `yaml:"author"`
}

type FingerprintPscan struct {
	Path        []string `yaml:"path"`
	Expressions []string `yaml:"expressions"`
}

type FingerprintRule struct {
	Engine string           `yaml:"engine"`
	Info   FingerprintInfo  `yaml:"info"`
	Pscan  FingerprintPscan `yaml:"pscan"`
}

//go:embed technologies/wscan
var template embed.FS

func readDir(dir string, fs embed.FS) ([]FingerprintRule, error) {
	ret := []FingerprintRule{}
	entries, err := fs.ReadDir(dir)
	if err != nil {
		logger.Error(err.Error())
		return ret, err
	}
	for _, entry := range entries {
		if entry.IsDir() {
			// 如果是目录，则递归读取子目录
			subRet, _ := readDir(dir+"/"+entry.Name(), fs)
			ret = append(ret, subRet...)
		} else {
			// 如果是文件，则读取文件内容或者进行其他操作
			fileContent, err := fs.ReadFile(dir + "/" + entry.Name())
			if err != nil {
				return ret, err
			}
			fpr := FingerprintRule{}
			if err = yaml.Unmarshal(fileContent, &fpr); err != nil {
				logger.Error(err.Error())
				return ret, err
			}
			ret = append(ret, fpr)
		}
	}

	return ret, nil
}

func LoadFingerprintRule(ruleFile string) (*FingerprintRule, error) {
	return nil, nil
}

var fingerprintRules []FingerprintRule

func ProcessFingerprint(ctx context.Context, res resource.Resource) {

}

type Config struct {
	base.PluginBaseConfig `json:",inline" yaml:",inline"`
	// 可添加其它配置项，例如
	// AESKey                []string `json:"aes_key" yaml:"aes_key" #:"自定义 shiro key，配置后将与内置 100 key 做合并"`
}

// BaseConfig 返回基本配置, 固定格式, 无需修改
func (c *Config) BaseConfig() *base.PluginBaseConfig {
	return &c.PluginBaseConfig
}

type Fingerprint struct {
	base.PluginMixinInitConfig
	base.PluginMixinClose
}

// Close 关闭函数
func (p *Fingerprint) Close() error {
	return nil
}

// DefaultConfig 返回默认配置, 需要填写插件的默认配置
func (p *Fingerprint) DefaultConfig() base.PluginConfigInterface {
	config := &Config{PluginBaseConfig: base.PluginBaseConfig{
		Name:       "fingerprint",
		Enabled:    true,
		IsAdvanced: true,
	}}
	return config
}

// Fingers 返回漏洞检测配置
func (p *Fingerprint) Fingers() []*base.Finger {
	fingers := []*base.Finger{}
	fingers = append(fingers, &base.Finger{
		CheckAction: p.execAction,
		Channel:     "web-generic",
		Binding:     &model.VulnBinding{ID: "fingerprint/default", Plugin: "fingerprint", Category: "fingerprint", Severity: model.SeverityInfo},
	})
	return fingers
}

// GetConfig 获取配置
func (p *Fingerprint) GetConfig() base.PluginConfigInterface {
	return p.PluginMixinInitConfig.GetConfig()
}

// Init 插件初始化
func (p *Fingerprint) Init(ctx context.Context, pci base.PluginConfigInterface, ab *base.ApolloBase) error {
	logger.Debug("fingerprint init")
	return p.PluginMixinInitConfig.Init(ctx, pci, ab)
}

// execAction 执行漏洞检测
func (p *Fingerprint) execAction(ctx context.Context, ab *base.Apollo) error {
	flow := ab.GetTargetFlow()
	logger.Debugf("Fingerprint Detection, URL=%s", flow.Request.URL().String())
	req := flow.Request
	rep := flow.Response
	ce := helper.NewCelExecutor()
	defer ce.Close()
	protoRequest, err := helper.ConvertHttpRequestToModelRequest(req)
	if err != nil {
		logger.Error(err.Error())
		return err
	}
	protoResponse, err := helper.ConvertHttpResponseToModelResponse(rep, rep.TimeStamp-req.TimeStamp)
	if err != nil {
		logger.Error(err.Error())
		return err
	}
	ce.SetVariable("request", protoRequest)
	ce.SetVariable("response", protoResponse)
	for _, fingerprintRule := range fingerprintRules {
		for _, expression := range fingerprintRule.Pscan.Expressions {
			successVal, err := ce.Evaluate(expression)
			if err != nil {
				// wrappedErr := errors.Wrapf(err, "Evalute Fingerprint[%s] expression error: %s", fingerprintRule.Info.Name, expression)
				// logger.Error(wrappedErr.Error())
				continue
			}
			if isFound, ok := successVal.Value().(bool); ok && isFound {
				if ab.KDB.SaveFingerprint(flow, fingerprintRule.Info.Name) {
					logger.Infof("Found Fingerprint %s", fingerprintRule.Info.Name)
					fp := &model.Vuln{
						Payload:    expression,
						Param:      nil,
						Flow:       []*http.Flow{{Request: req, Response: rep}},
						Binding:    &model.VulnBinding{Plugin: fingerprintRule.Info.Name, Category: fingerprintRule.Info.Name, ID: fingerprintRule.Info.Name, Severity: model.SeverityInfo},
						Extra:      make(map[string]any),
						CreateTime: time.Now().Unix(),
					}
					fp.SetTargetURL(req.URL())
					ab.OutputVuln(fp)
				}
			}
		}
	}
	return nil
}

func init() {
	rules, err := readDir("technologies/wscan", template)
	if err != nil {
		logger.Fatal(err.Error())
	}
	logger.Infof("累计加载 %d个Web组件指纹插件", len(rules))
	fingerprintRules = rules
}
