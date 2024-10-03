/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package output

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/kataras/pio"
	"net/url"
	"wscan/core/http"
	"wscan/core/model"
	logger "wscan/core/utils/log"
	"wscan/core/utils/printer"
	"wscan/core/utils/printer/nice"
)

func NewWebHookPrinter(url *url.URL) *webHookPrinter {
	return &webHookPrinter{
		url:    url,
		client: http.NewClient(),
	}
}

type webHookPrinter struct {
	ctx    context.Context
	url    *url.URL
	header map[string][]string
	client *http.Client
}

type WebHookRequest struct {
	Type string      `json:"type" yaml:"type"`
	Data interface{} `json:"data"`
}

func (p *webHookPrinter) AddInterceptor(func(interface{}) (interface{}, error)) printer.Printer {
	return nil
}

func (p *webHookPrinter) Close() error {
	return nil
}

func (p *webHookPrinter) LogStats(lastStat *model.StatisticRecord) error {
	p.sendReq(&WebHookRequest{
		Type: "web_statistic",
		Data: lastStat,
	})
	return nil
}

func (p *webHookPrinter) LogSubdomain(*model.SubDomainResult) error {
	return nil
}
func (p *webHookPrinter) LogVuln(vuln *model.Vuln) error {
	p.sendReq(&WebHookRequest{
		Type: "web_vuln",
		Data: vuln.ToWebVuln(),
	})
	return nil
}

func (p *webHookPrinter) Print(res interface{}) error {
	switch res.(type) {
	case *model.Vuln:
		vuln := res.(*model.Vuln)
		p.LogVuln(vuln)
	case *model.StatisticRecord:
		lastStat := res.(*model.StatisticRecord)
		p.LogStats(lastStat)
	case *model.CrawlerResult:
		return nil
	default:
		nice.PioPrinter.Println(pio.Rich(fmt.Sprintf("%v", res), pio.Red))
	}
	return nil
}

func (p *webHookPrinter) sendReq(webHookReq *WebHookRequest) {
	data, _ := json.Marshal(webHookReq)
	req, err := http.NewRequest("POST", p.url.String(), bytes.NewReader(data))
	if err != nil {
		logger.Error(err)
	}
	_, err = p.client.DoRaw(req)
	if err != nil {
		logger.Error(err)
	}
}

func (*webHookPrinter) truncResult([]byte) []byte {
	return nil
}
