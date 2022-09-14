/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package model

import (
	"net/http"
	"net/url"
	vhttp "wscan/core/assassin/http"
	"wscan/core/assassin/resource"
)

//gunkit/core/assassin/model.NewServiceVuln

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

func (*Vuln) Add(string, string) *Vuln {
	return nil
}
func (*Vuln) AddMap(string, map[string]interface{}) *Vuln {
	return nil
}
func (*Vuln) AddStringArray(string, []string) *Vuln {
	return nil
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
func (*Vuln) SetTargetURL(*url.URL) {
	return
}
func (*Vuln) String() string {
	return ""
}
func (v *Vuln) Target() resource.Resource {
	return nil
}
func (*Vuln) TargetURL() *url.URL {
	return nil
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
