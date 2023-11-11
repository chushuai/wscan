/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package output

import (
	"context"
	"net/http"
	"net/url"
	"wscan/core/model"
	"wscan/core/utils/printer"
)

func NewWebHookPrinter() *webHookPrinter {
	return &webHookPrinter{}
}

type webHookPrinter struct {
	ctx    context.Context
	url    *url.URL
	header map[string][]string
	client *http.Client
}

func (*webHookPrinter) AddInterceptor(func(interface{}) (interface{}, error)) printer.Printer {
	return nil
}
func (*webHookPrinter) Close() error {
	return nil
}
func (*webHookPrinter) LogStats(*model.StatisticRecord) error {
	return nil
}
func (*webHookPrinter) LogSubdomain(*model.SubDomainResult) error {
	return nil
}
func (*webHookPrinter) LogVuln(*model.Vuln) error {
	return nil
}
func (*webHookPrinter) Print(interface{}) error {
	return nil
}
func (*webHookPrinter) sendReq() {

}
func (*webHookPrinter) truncResult([]uint8) []uint8 {
	return nil
}
