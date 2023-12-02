/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package model

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	vhttp "wscan/core/http"
	"wscan/core/resource"
)

func NewWebVuln() {

}

type Extra struct {
	SourceName string `json:"source" yaml:"source"`
	Detail     string `json:"detail" yaml:"detail"`
}

type IPInfo struct {
	IP      string `json:"ip" yaml:"ip"`
	ASN     string `json:"asn" yaml:"asn"`
	Country string `json:"country" yaml:"country"`
}

type NSStat struct {
	Server     string
	SuccessNum int
	FailedNum  int
	AvgTime    int32
}

type ParamInfo struct {
	Position string   `json:"position"`
	Path     []string `json:"path"`
}

type SourceMeta struct {
	SourceType  string `json:"-" yaml:"-"`
	VerboseName string `json:"verbose_name" yaml:"verbose_name"`
	ReadTimeout int64  `json:"-" yaml:"-"`
}

type SubDomainResult struct {
	SourceMeta
	Parent string     `json:"parent" yaml:"parent"`
	Domain string     `json:"domain" yaml:"domain"`
	CNAME  []string   `json:"cname" yaml:"cname"`
	IP     []*IPInfo  `json:"ip" yaml:"ip"`
	Web    []*WebInfo `json:"web" yaml:"web"`
	Extra  []Extra    `json:"extra" yaml:"extra"`
	stat   uint8
}

type StatisticRecord struct {
	NumFoundUrls            int64   `json:"num_found_urls"`
	NumScannedUrls          int64   `json:"num_scanned_urls"`
	NumSentHTTPRequests     int64   `json:"num_sent_http_requests"`
	AverageResponseTime     float32 `json:"average_response_time"`
	RatioFailedHTTPRequests float32 `json:"ratio_failed_http_requests"`
	RatioProgress           float32 `json:"ratio_progress"`
}

type SubdomainStatistic struct {
	NumFound int
	Target   string
	//HTTP     *http.StatRepr
	DNS []*NSStat
}

type WebInfo struct {
	Link   string   `json:"link" yaml:"link"`
	Status int      `json:"status" yaml:"link"`
	Title  string   `json:"title" yaml:"title"`
	Server string   `json:"server" yaml:"server"`
	Tags   []string `json:"-" yaml:"-"`
}

type WebTarget struct {
	URL    string      `json:"url"`
	Params []ParamInfo `json:"params,omitempty"`
}

type VulnBinding struct {
	Plugin   string
	Category string
	ID       string
}

type VulnDetail struct {
	Addr     string                 `json:"addr" yaml:"addr"`
	Payload  string                 `json:"payload" yaml:"payload"`
	SnapShot []interface{}          `json:"snapshot" yaml:"snapshot"`
	Extra    map[string]interface{} `json:"extra" yaml:"extra"`
}

type WebVuln struct {
	Plugin     string     `json:"plugin"`
	Detail     VulnDetail `json:"detail"`
	CreateTime int64      `json:"create_time"`
	Target     WebTarget  `json:"target"`
}

type Vuln struct {
	client     *http.Client
	target     resource.Resource
	Type       int
	Binding    *VulnBinding
	Extra      map[string]interface{}
	targetURL  *url.URL
	Flow       []*vhttp.Flow
	Payload    string
	Param      *vhttp.Parameter
	CreateTime int64
}

func (v *Vuln) Add(key string, value string) *Vuln {
	v.Extra[key] = value
	return v
}

func (v *Vuln) AddMap(key string, value map[string]interface{}) *Vuln {
	v.Extra[key] = value
	return v
}

func (v *Vuln) AddStringArray(key string, value []string) *Vuln {
	v.Extra[key] = value
	return v
}

func (*Vuln) AddUsernamePassword(string, string, []string) *Vuln {
	return nil
}

func (*Vuln) GetPassword() (string, string) {
	return "", ""
}

func (*Vuln) GetUsername() (string, string) {
	return "", ""
}

func (*Vuln) MarshalJSON() ([]uint8, error) {
	return nil, nil
}

func (v *Vuln) SetTargetURL(u *url.URL) {
	v.targetURL = u
}

func (v *Vuln) String() string {
	raw := fmt.Sprintf("[Vuln: %v]\n", v.Binding.Category)
	if v.TargetURL() != nil {
		raw += fmt.Sprintf("Target			%v\n", v.TargetURL().String())
	}
	if v.Payload != "" {
		raw += fmt.Sprintf("VulnType		%v\n", v.Binding.Plugin)
	}
	if v.Payload != "" {
		raw += fmt.Sprintf("Payload			%v\n", v.Payload)
	}
	if v.Param != nil {
		raw += fmt.Sprintf("Position		%s\n", v.Param.Position)
		raw += fmt.Sprintf("ParamKey		%s\n", v.Param.Key)
		raw += fmt.Sprintf("ParamValue		%s\n", v.Param)
	}
	if len(v.Extra) > 0 {
		if data, err := json.Marshal(v.Extra); err == nil {
			raw += fmt.Sprintf("Extra			%s\n", string(data))
		}
	}
	return raw
}

func (v *Vuln) Target() resource.Resource {
	return v.target
}

func (v *Vuln) TargetURL() *url.URL {
	return v.targetURL
}

func (*Vuln) ToMap() map[string]interface{} {
	return nil
}

func (*Vuln) UnmarshalJSON([]uint8) error {
	return nil
}

func (*Vuln) serviceRaw() map[string]interface{} {
	return nil
}

func (*Vuln) webRaw() map[string]interface{} {
	return nil
}

func (vuln *Vuln) ToWebVuln() *WebVuln {
	webVuln := WebVuln{
		Plugin: vuln.Binding.Plugin,
		Detail: VulnDetail{
			Addr:    vuln.TargetURL().String(),
			Payload: vuln.Payload,
			Extra:   vuln.Extra,
		},
		Target: WebTarget{
			URL: vuln.TargetURL().String(),
		},
		CreateTime: vuln.CreateTime,
	}
	if vuln.Param != nil {
		webVuln.Target.Params = []ParamInfo{
			{Position: vuln.Param.Position, Path: []string{vuln.Param.Key}},
		}
	}
	for _, flow := range vuln.Flow {
		webVuln.Detail.SnapShot = append(webVuln.Detail.SnapShot, []string{
			string(flow.Request.Dump()),
			string(flow.Response.Dump()),
		})
	}
	return &webVuln
}
