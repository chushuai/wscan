/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package comparer

import (
	"fmt"
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

func CompareResponse(response1, response2 *http.Response) bool {
	hp := htmlcompare.NewHTMLProcessorFromString(response1.Text)
	hp2 := htmlcompare.NewHTMLProcessorFromString(response2.Text)
	fmt.Println("CompareHTMLProcessors=", htmlcompare.CompareHTMLProcessors(hp, hp2))
	return htmlcompare.CompareHTMLProcessors(hp, hp2) == 1.0
}
