/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package xss

import (
	"context"
	"github.com/PuerkitoBio/goquery"
	"golang.org/x/net/html"
	"wscan/core/assassin/http"
	"wscan/core/assassin/plugins/base"
	"wscan/core/utils/checker"
	logger "wscan/core/utils/log"
)

type Element struct {
	node       *html.Node
	name       string
	attributes map[string]string
	text       string
}

type QueryResponse struct {
	request  *http.Request
	response *http.Response
	doc      *goquery.Document
}

type Config struct {
	base.PluginBaseConfig `json:",inline" yaml:",inline"`
	DetectXSSInCookie     bool `json:"detect_xss_in_cookie" yaml:"detect_xss_in_cookie" #:"是否探测入口点在 cookie 中的 xss"`
	DetectXSSInReferer    bool `json:"detect_xss_in_referer" yaml:"detect_xss_in_referer" #:"是否探测入口点在 referer 中的 xss"`
	IEFeature             bool `json:"ie_feature" yaml:"ie_feature" #:"是否扫描仅能在 ie 下利用的 xss"`
}

func (c *Config) BaseConfig() *base.PluginBaseConfig {
	return &c.PluginBaseConfig
}

type XSS struct {
	base.PluginMixinInitConfig
	base.PluginMixinClose
	Client             *http.Client
	bfBase             *base.BifrostBase
	cookieDomainFilter *checker.URLChecker
	refererFilter      *checker.URLChecker
}

type requestBuilder struct {
	prefix       string
	suffix       string
	request      *http.Request
	parameter    *http.Parameter
	last_payload string
}

func (p *XSS) AddXSSVuln(context.Context, *http.Request, *http.Response, *http.Parameter, string) {

}

func (p *XSS) Fingers() []*base.Finger {
	return nil
}

func (p *XSS) checkContentCheatHeader() {

}

func (p *XSS) checkContentType() {

}
func (p *XSS) checkVulnerability() {

}

func (p *XSS) execAction(context.Context, *base.Bifrost) error {
	return nil
}

func (p *XSS) handleAttrKey() {

}

func (p *XSS) handleAttrValue() {

}
func (p *XSS) handleComment() {

}
func (p *XSS) handleData() {

}
func (p *XSS) handleHref() {

}
func (p *XSS) handleScript() {

}
func (p *XSS) handleStyle() {

}
func (p *XSS) handleTag() {

}
func (p *XSS) handleTagName() {

}
func (p *XSS) handleText() {

}
func (p *XSS) handleUTF7() {

}
func (p *XSS) requestForQuery() {

}
func (p *XSS) walkAParameter() {

}

func (p *XSS) Close() error {
	return nil
}

func (p *XSS) DefaultConfig() base.PluginConfigInterface {
	config := &Config{PluginBaseConfig: base.PluginBaseConfig{
		Name:    "xss",
		Enabled: true,
	}, DetectXSSInCookie: true, DetectXSSInReferer: true, IEFeature: true}
	return config
}

func (p *XSS) GetConfig() base.PluginConfigInterface {
	return p.PluginMixinInitConfig.GetConfig()
}

func (p *XSS) Scan() func(context.Context) error {
	return nil
}

func (p *XSS) Init(ctx context.Context, pfi base.PluginConfigInterface, bb *base.BifrostBase) error {
	logger.Info("XSS Plugin init")
	p.PluginMixinInitConfig.Init(ctx, pfi, bb)
	return nil
}
