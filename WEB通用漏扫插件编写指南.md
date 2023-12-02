WEB通用漏扫插件编写指南
````
Config
 BaseConfig()  返回基本配置, 固定格式，无需修改。

WebVulnPlugin
 Close() 关闭函数。
 DefaultConfig() 返回默认配置。需要填写插件的默认配置。
 Fingers() 请在这里面注册你的回调函数, 每个Finger代表一个检查项目，调度的时候Finger之间是并行的
 GetConfig()  获取配置。。固定格式，无需修改 请参考示例。
 Init
````


参考示例
```
package web_vuln_plugin

import (
    "context"
    "wscan/core/http"
	"wscan/core/model"
	"wscan/core/plugins/base"
    logger "wscan/core/utils/log"
)

type Config struct {
    base.PluginBaseConfig `json:",inline" yaml:",inline"`
    // 可添加其它配置项，例如
    // AESKey                []string `json:"aes_key" yaml:"aes_key" #:"自定义 shiro key，配置后将与内置 100 key 做合并"`
}

// BaseConfig 返回基本配置, 固定格式, 无需修改
func (c *Config) BaseConfig() *base.PluginBaseConfig {
    return &c.PluginBaseConfig
}

type WebVulnPlugin struct {
    base.PluginMixinInitConfig
    base.PluginMixinClose
}

// Close 关闭函数
func (*WebVulnPlugin) Close() error {
    return nil
}

// DefaultConfig 返回默认配置, 需要填写插件的默认配置
func (*WebVulnPlugin) DefaultConfig() base.PluginConfigInterface {
    return &Config{}
}

// Fingers 返回漏洞检测配置
func (p *WebVulnPlugin) Fingers() []*base.Finger {
    fingers := []*base.Finger{}
    fingers = append(fingers, &base.Finger{
        CheckAction: p.execAction,
        Channel:     "web-generic",
     	Binding:     &model.VulnBinding{ID: "web-vuln-plugin/web-vuln-plugin/default", Plugin: "web-vuln-plugin/web-vuln-plugin", Category: "web-vuln-plugin"},
    })
    return fingers
}

// GetConfig 获取配置
func (p *WebVulnPlugin) GetConfig() base.PluginConfigInterface {
    return p.PluginMixinInitConfig.GetConfig()
}

// Init 插件初始化
func (p *WebVulnPlugin) Init(ctx context.Context, pci base.PluginConfigInterface, ab *base.ApolloBase) error {
    logger.Info("WebVulnPlugin init")
    return p.PluginMixinInitConfig.Init(ctx, pci, ab)
}

// execAction 执行漏洞检测
func (p *WebVulnPlugin) execAction(ctx context.Context, ab *base.Bifrost) error {
    flow := ab.GetTargetFlow()
    logger.Infof("开始检测web漏洞, URL=%s", flow.Request.URL.String())
    
    payloads = []string{"具体payload"}
    // 遍历url和body中的参数
    for _, param := range flow.Request.ParamsQueryAndBody() {
        for _, payload := range payloads {
            logger.Infof("%s, Test vulnerability= %s", flow.Request.URL.String(), rule.Vector)
            // 对指定的参数进行形变，支持url、json、xml等类型的参数
            req := flow.Request.Mutate(&http.Parameter{Position: param.Position, Key: param.Key, Value: param.Value, Suffix: payload})
            // 发送请求
            res, err := b.HTTPClient.Respond(context.TODO(), req)
            if err != nil {
                continue
            }
            if rule.compiled.Match([]byte(res.Text)) {
                v := ab.NewWebVuln(req, res, &param)
                if v != nil {
                    v.SetTargetURL(&flow.Request.URL)
                    v.Payload = payload
                    b.OutputVuln(v)
                }
            }
        }
    }

    return nil
}


```