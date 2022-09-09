/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package base

import (
	"github.com/google/martian/v3/filter"
	"golang.org/x/net/context"
	"net/http"
	"sync"
	"wscan/core/assassin/model"
	"wscan/core/assassin/plugins/helper/knowledge"
	"wscan/core/assassin/resource"
	"wscan/core/assassin/reverse"
	"wscan/core/utils/checker"
	"wscan/core/utils/printer"
)

type BifrostBase struct {
	HTTPClient      *http.Client
	KDB             *knowledge.KnowledgeDB
	Reverse         *reverse.Reverse
	Output          printer.Printer
	FilterContainer filter.Filter
	FilterConfig    *checker.RequestCheckerConfig
	ctx             context.Context
	cancel          func()
	clone           bool
	vuln            *model.Vuln
}

type Bifrost struct {
	sync.Mutex
	*BifrostBase
	tempDB  *sync.Map
	binding *model.VulnBinding
	target  resource.Resource
}

func (*BifrostBase) Close() {

}

func (*BifrostBase) GetVulnToTest() *model.Vuln {
	return nil
}

func (*BifrostBase) IsRetesting() bool {
	return false
}
func (*BifrostBase) NewBrowser(int) error {
	return /*nil,*/ nil
}
func (*BifrostBase) NewRequestChecker() (*checker.RequestChecker, error) {
	return nil, nil
}
func (*BifrostBase) NewURLChecker() (*checker.URLChecker, error) {
	return nil, nil
}

func (*BifrostBase) StatusLogError(string) {

}
func (*BifrostBase) StatusLogInfo(string) {

}
func (*BifrostBase) StatusLogWarn(string) {

}
func (*BifrostBase) WithClone(bool) *BifrostBase {
	return nil
}
func (*BifrostBase) WithContext(context.Context) *BifrostBase {
	return nil
}
func (*BifrostBase) WithVuln(*model.Vuln) {

}

func (Bifrost) Close() {}
func (Bifrost) GetVulnToTest() *model.Vuln {
	return nil
}
func (Bifrost) IsRetesting() bool {
	return false
}
func (Bifrost) NewBrowser(int) error {
	return /*nil,*/ nil
}
func (Bifrost) NewRequestChecker() (*checker.RequestChecker, error) {
	return nil, nil
}
func (Bifrost) NewURLChecker() (*checker.URLChecker, error) {
	return nil, nil
}
func (Bifrost) StatusLogError(string) {

}
func (Bifrost) StatusLogInfo(string) {

}
func (Bifrost) StatusLogWarn(string) {

}
func (Bifrost) WithClone(bool) *BifrostBase {
	return nil
}
func (Bifrost) WithContext(context.Context) *BifrostBase {
	return nil
}
func (Bifrost) WithVuln(*model.Vuln) {

}
