/**
2 * @Author: shaochuyu
3 * @Date: 7/2/22
4 */

package collector

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"testing"
)

func agentPluginRun(args interface{}) {
	if p, ok := args.(*PassiveProxy); ok {
		go func() {
			for {
				Url := <-p.CommunicationSingleton
				data, _ := json.Marshal(Url)
				fmt.Println(string(data))
			}
		}()
	}
}

func TestProxy(t *testing.T) {
	// var req *http.Request
	// cookies := req.Cookies()

	// for _, cookie := range cookies {
	// 	cookie.String()
	// }
	s := SProxy{}
	s.CallbackFunc = agentPluginRun
	s.Run()
}

func Test_cProxy(t *testing.T) {
	urli := url.URL{}
	urlproxy, _ := urli.Parse("http://127.0.0.1:8080")
	c := http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(urlproxy),
		},
	}
	tests := []string{"http://51.187.222.161", "http://95.122.83.54:80"}
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
