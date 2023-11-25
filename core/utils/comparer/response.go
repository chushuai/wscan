/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package comparer

import (
	"wscan/core/http"
	"wscan/core/utils/comparer/htmlcompare"
)

func is3xx() bool {
	return false
}

func getSetCookieKey() {
}

func filterBody() {
}

func CompareResponse(response1, response2 *http.Response) float32 {
	hp := htmlcompare.NewHTMLProcessorFromString(response1.Text)
	hp2 := htmlcompare.NewHTMLProcessorFromString(response2.Text)
	return htmlcompare.CompareHTMLProcessors(hp, hp2)
}
