/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package xss

import (
	"context"
	"github.com/PuerkitoBio/goquery"
	"golang.org/x/net/html"
	"strings"
	"wscan/core/http"
	"wscan/core/model"
	"wscan/core/plugins/base"
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
	bfBase             *base.Apollo
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

// getCommonPayload is return xss
func getXSSPayload() []string {
	payload := []string{
		// include verify payload
		"<scRipt>Wscan(WSCAN_ALERT_VALUE)</scRipt>",
		//"\"><SvG/onload=alert(DALFOX_ALERT_VALUE) id=dalfox>",
		//"\"><Svg/onload=alert(DALFOX_ALERT_VALUE) class=dlafox>",
		//"'><sVg/onload=alert(DALFOX_ALERT_VALUE) id=dalfox>",
		//"'><sVg/onload=alert(DALFOX_ALERT_VALUE) class=dalfox>",
		//"</ScriPt><sCripT id=dalfox>alert(DALFOX_ALERT_VALUE)</sCriPt>",
		//"</ScriPt><sCripT class=dalfox>alert(DALFOX_ALERT_VALUE)</sCriPt>",
		//"\"><a href=javas&#99;ript:alert(DALFOX_ALERT_VALUE)/class=dalfox>click",
		//"'><a href=javas&#99;ript:alert(DALFOX_ALERT_VALUE)/class=dalfox>click",
		//"'><svg/class='dalfox'onLoad=alert(DALFOX_ALERT_VALUE)>",
		//"\"><d3\"<\"/onclick=\" class=dalfox>[confirm``]\"<\">z",
		//"\"><w=\"/x=\"y>\"/class=dalfox/ondblclick=`<`[confir\u006d``]>z",
		//"\"><iFrAme/src=jaVascRipt:alert(DALFOX_ALERT_VALUE) class=dalfox></iFramE>",
		//"\"><svg/class=\"dalfox\"onLoad=alert(DALFOX_ALERT_VALUE)>",
		//"'\"><svg/class=dalfox onload=&#97&#108&#101&#114&#00116&#40&#41&#x2f&#x2f",
		//"</script><svg><script/class=dalfox>alert(DALFOX_ALERT_VALUE)</script>-%26apos;",
		//"'\"><iframe srcdoc=\"<input onauxclick=alert(DALFOX_ALERT_VALUE)>\" class=dalfox></iframe>",
		//"<xmp><p title=\"</xmp><svg/onload=alert(DALFOX_ALERT_VALUE)>",
		//"\"><a href=\"javascript&colon;alert(DALFOX_ALERT_VALUE)\">click",
		//"'><a href='javascript&colon;alert(DALFOX_ALERT_VALUE)'>click",
		//"\"><iFrAme/src=jaVascRipt:alert(DALFOX_ALERT_VALUE)></iFramE>",
	}
	return payload
}

func (p *XSS) AddXSSVuln(context.Context, *http.Request, *http.Response, *http.Parameter, string) {

}

func (p *XSS) Fingers() []*base.Finger {
	fingers := []*base.Finger{}
	fingers = append(fingers, &base.Finger{
		CheckAction: func(ctx context.Context, bi *base.Apollo) error {
			flow := bi.GetTargetFlow()
			logger.Debugf("开始检测XSS, URL=%s", flow.Request.URL().String())
			for _, param := range flow.Request.ParamsQueryAndBody() {
				for _, xssPayload := range getXSSPayload() {
					logger.Debugf("%s, Test XSS Payload= %s", flow.Request.URL().String(), xssPayload)
					req := flow.Request.Mutate(&http.Parameter{Position: param.Position, Key: param.Key, Value: param.Value, Suffix: xssPayload})
					res, err := bi.HTTPClient.Respond(context.TODO(), req)
					if err != nil {
						continue
					}
					if strings.Contains(res.Text, "WSCAN_ALERT_VALUE") {
						v := bi.NewWebVuln(req, res, &param)
						if v != nil {
							v.SetTargetURL(flow.Request.URL())
							v.Payload = xssPayload
							bi.OutputVuln(v)
						}
					}
				}
			}
			return nil
		},
		Channel: "web-generic",
		Binding: &model.VulnBinding{ID: "xss/reflected/default", Plugin: "xss/reflected", Category: "xss"},
	})
	return fingers
}
func (p *XSS) checkContentCheatHeader() {

}

func (p *XSS) checkContentType() {

}
func (p *XSS) checkVulnerability() {

}

func (p *XSS) execAction(context.Context, *base.Apollo) error {
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

func (p *XSS) Init(ctx context.Context, pfi base.PluginConfigInterface, bb *base.ApolloBase) error {
	logger.Info("XSS Plugin init")
	p.PluginMixinInitConfig.Init(ctx, pfi, bb)
	return nil
}
