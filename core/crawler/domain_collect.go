/**
2 * @Author: shaochuyu
3 * @Date: 12/9/22
4 */
package crawler

import (
	mapset "github.com/deckarep/golang-set"
	"net/http"
	"strings"
)

func SubDomainCollect(reqList []*http.Request, HostLimit string) []string {
	var subDomainList []string
	uniqueSet := mapset.NewSet()
	for _, req := range reqList {
		domain := req.URL.Hostname()
		if uniqueSet.Contains(domain) {
			continue
		}
		uniqueSet.Add(domain)
		if strings.HasSuffix(domain, "."+HostLimit) {
			subDomainList = append(subDomainList, domain)
		}
	}
	return subDomainList
}

func AllDomainCollect(reqList []*http.Request) []string {
	uniqueSet := mapset.NewSet()
	var allDomainList []string
	for _, req := range reqList {
		domain := req.URL.Hostname()
		if uniqueSet.Contains(domain) {
			continue
		}
		uniqueSet.Add(domain)
		allDomainList = append(allDomainList, req.URL.Hostname())
	}
	return allDomainList
}
