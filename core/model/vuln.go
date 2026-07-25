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
	"time"
	vhttp "wscan/core/http"
	"wscan/core/resource"
)

// TODO: implement NewWebVuln or remove
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

type CrawlerResult struct {
	Url     string            `json:"url"`
	Method  string            `json:"method"`
	Headers map[string]string `json:"headers"`
	Data    string            `json:"data"`
	Source  string            `json:"source"`
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

type SeverityLevel string

const (
	SeverityInfo     SeverityLevel = "info"
	SeverityLow      SeverityLevel = "low"
	SeverityMedium   SeverityLevel = "medium"
	SeverityHigh     SeverityLevel = "high"
	SeverityCritical SeverityLevel = "critical"
)

var SeverityOrder = map[SeverityLevel]int{
	SeverityInfo:     0,
	SeverityLow:      1,
	SeverityMedium:   2,
	SeverityHigh:     3,
	SeverityCritical: 4,
}

type VulnBinding struct {
	Plugin   string
	Category string
	ID       string
	Severity SeverityLevel
}

type VulnFilterConfig struct {
	MinSeverity  string   `json:"min_severity" yaml:"min_severity"`
	ExcludeVulns []string `json:"exclude_vulns" yaml:"exclude_vulns"`
	IncludeVulns []string `json:"include_vulns" yaml:"include_vulns"`
}

type VulnDetail struct {
	Addr     string         `json:"addr" yaml:"addr"`
	Payload  string         `json:"payload" yaml:"payload"`
	SnapShot []any          `json:"snapshot" yaml:"snapshot"`
	Extra    map[string]any `json:"extra" yaml:"extra"`
}

type WebVuln struct {
	Plugin     string        `json:"plugin"`
	Severity   SeverityLevel `json:"severity"`
	Detail     VulnDetail    `json:"detail"`
	CreateTime int64         `json:"create_time"`
	Target     WebTarget     `json:"target"`
}

type Vuln struct {
	client     *http.Client
	target     resource.Resource
	Type       int
	Binding    *VulnBinding
	Extra      map[string]any
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

func (v *Vuln) Get(key string) any {
	return v.Extra[key]
}

func (v *Vuln) AddMap(key string, value map[string]any) *Vuln {
	v.Extra[key] = value
	return v
}

func (v *Vuln) AddStringArray(key string, value []string) *Vuln {
	v.Extra[key] = value
	return v
}

// TODO: implement AddUsernamePassword
func (*Vuln) AddUsernamePassword(string, string, []string) *Vuln {
	return nil
}

// TODO: implement GetPassword
func (*Vuln) GetPassword() (string, string) {
	return "", ""
}

// TODO: implement GetUsername
func (*Vuln) GetUsername() (string, string) {
	return "", ""
}

// TODO: implement MarshalJSON
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

// TODO: implement ToMap
func (*Vuln) ToMap() map[string]any {
	return nil
}

// TODO: implement UnmarshalJSON
func (*Vuln) UnmarshalJSON([]uint8) error {
	return nil
}

// TODO: implement serviceRaw
func (*Vuln) serviceRaw() map[string]any {
	return nil
}

// TODO: implement webRaw
func (*Vuln) webRaw() map[string]any {
	return nil
}

func (vuln *Vuln) ToWebVuln() *WebVuln {
	webVuln := WebVuln{
		Plugin:   vuln.Binding.Plugin,
		Severity: vuln.Binding.Severity,
		Detail: VulnDetail{
			Addr:    vuln.TargetURL().String(),
			Payload: vuln.Payload,
			Extra:   vuln.Extra,
		},
		Target: WebTarget{
			URL: vuln.TargetURL().String(),
		},
		CreateTime: time.Now().UnixMilli(),
	}
	if vuln.Param != nil {
		webVuln.Target.Params = []ParamInfo{
			{Position: vuln.Param.Position, Path: []string{vuln.Param.Key}},
		}
		vuln.Extra["param"] = map[string]string{
			"key":      vuln.Param.Key,
			"position": vuln.Param.Position,
			"value":    vuln.Param.String(),
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
