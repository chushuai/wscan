/*
*
2 * @Author: shaochuyu
3 * @Date: 1/13/26
4
*/
package crawler

import (
	"fmt"
	"wscan/core/http"

	"github.com/PuerkitoBio/goquery"
)

func headerContentLocationParser(u *http.URL, doc *goquery.Document, resp *http.Response) {
	header := resp.Header.Get("Content-Location")
	if header == "" {
		return
	}
	newUrl, _ := http.GetUrl(header, *u)
	req, err := http.NewRequest("GET", newUrl.String(), nil)
	fmt.Println(req, err)
}
