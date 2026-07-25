/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package redirect

import (
	"github.com/PuerkitoBio/goquery"
	"net/url"
)

type domRedirect struct {
	doc     *goquery.Document
	respURL *url.URL
}

func (*domRedirect) CheckMetaRedirect() (string, error) {
	return "", nil
}

func (*domRedirect) CheckScriptRedirect() (string, error) {

	return "", nil
}
