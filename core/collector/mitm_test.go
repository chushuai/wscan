/**
2 * @Author: shaochuyu
3 * @Date: 7/2/22
4 */

package collector

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"testing"
)

func Test_cProxy(t *testing.T) {
	urli := url.URL{}
	urlproxy, _ := urli.Parse("http://127.0.0.1:1000")
	c := http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(urlproxy),
		},
	}
	tests := []string{"http://testphp.vulnweb.com/"}
	for _, test := range tests {
		if resp, err := c.Get(test); err != nil {
			log.Fatalln(err)
		} else {
			defer resp.Body.Close()
			body, _ := ioutil.ReadAll(resp.Body)
			fmt.Println(string(body))
		}
	}
}
