/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package datasource

import (
	"context"
	"wscan/core/assassin/model"
	"wscan/ext/fastdomain/geodb"
	"wscan/ext/fastdomain/utils"
)

type alienvault struct {
	BaseSubDomainRunner
}

func (*alienvault) ChanToSlice(chan *model.SubDomainResult) []*model.SubDomainResult {
	return nil
}

func (*alienvault) Config() SubDomainConfig {
	return nil
}

func (*alienvault) Init(*RewriteTimeoutHTTPClient /**dns.Client,*/, SubDomainConfig, *utils.ConnectionConfig /* *log.Logger,*/, *geodb.Client) {

}

func (*alienvault) IsSubDomain(string, string) bool {
	return false
}

func (*alienvault) MatchSubDomain(string, []uint8) []*model.SubDomainResult {
	return nil
}

func (*alienvault) MatchSubDomainString(string, []uint8) []string {
	return nil
}

func (*alienvault) Meta() *model.SourceMeta {
	return nil
}

func (*alienvault) New() SubDomainRunner {
	return nil
}

func (*alienvault) Run(context.Context, *model.SubDomainResult) ([]*model.SubDomainResult, error) {
	return nil, nil
}

func (*alienvault) RunChan(context.Context, *model.SubDomainResult, interface{}) (chan *model.SubDomainResult, error) {
	return nil, nil
}

func (*alienvault) UpdateExtra(model.Extra, []*model.SubDomainResult) []*model.SubDomainResult {
	return nil
}

func (*alienvault) requestDataSource() {

}

func (*alienvault) resultUnion() {

}
