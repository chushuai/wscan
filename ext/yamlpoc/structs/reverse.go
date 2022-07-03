package structs

import (
	"net/http"
	"strings"
	"time"
)

var (
	CeyeApi                  string
	CeyeDomain               string
	ReversePlatformType      ReverseType
	DnslogCNGetDomainRequest *http.Request
	DnslogCNGetRecordRequest *http.Request
)

func InitReversePlatform(api, domain string, timeout time.Duration) {
	if api != "" && domain != "" && strings.HasSuffix(domain, ".ceye.io") {
		CeyeApi = api
		CeyeDomain = domain
		ReversePlatformType = ReverseType_Ceye
	} else {
		ReversePlatformType = ReverseType_DnslogCN

		// 设置请求相关参数
		DnslogCNGetDomainRequest, _ = http.NewRequest("GET", "http://dnslog.cn/getdomain.php", nil)
		DnslogCNGetRecordRequest, _ = http.NewRequest("GET", "http://dnslog.cn/getrecords.php", nil)

	}
}
