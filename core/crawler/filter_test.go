/**
2 * @Author: shaochuyu
3 * @Date: 12/2/23
4 */

package crawler

import (
	"testing"
	"wscan/core/http"
	logger "wscan/core/utils/log"
)

func TestDoFilter(t *testing.T) {
	smartFilter := SmartFilter{
		SimpleFilter: SimpleFilter{},
		StrictMode:   true,
	}
	smartFilter.Init()

	tests := []string{
		"https://demo.testfire.net/index.jsp?content=personal_savings.htm",
		"https://demo.testfire.net/index.jsp?content=privacy.htm",
		"https://demo.testfire.net/index.jsp?content=inside_careers.htm",
		"https://demo.testfire.net/index.jsp?content=inside_investor.htm",
		"https://demo.testfire.net/index.jsp?content=business_insurance.htm",
		"https://demo.testfire.net/index.jsp?content=business_cards.htm",
		"https://demo.testfire.net/images/inside6.jpg",
		"https://demo.testfire.net/application/x-shockwave-flash",
		"https://demo.testfire.net/disclaimer.htm?url=http://www.microsoft.com",
		"https://demo.testfire.net/disclaimer.htm?url=http://www.netscape.com",
		"http://demo.testfire.net/disclaimer.htm?url=http://www.netscape.com",
		"http://demo.testfire.net/disclaimer.htm?url=http://www.microsoft.com",
		"http://pu2lh35z.ia.aqlab.cn/",
		"https://pu2lh35z.ia.aqlab.cn/",
	}
	for _, test := range tests {
		req, _ := http.NewRequest("GET", test, nil)
		logger.Infof("%v, %s", smartFilter.DoFilter(req, false), test)
		// UniqueFilter
	}
}
