/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package datasource

import (
	"context"
	mapset "github.com/deckarep/golang-set"
	"log"
	"sync"
	"wscan/core/fastdomain/dns"
	"wscan/core/fastdomain/geodb"
	"wscan/core/fastdomain/model"
	"wscan/core/fastdomain/utils"
)

type RewriteTimeoutHTTPClient struct {
	//*http.Client
	Timeout int64
}

type SubDomainConfig interface {
	Clone() SubDomainConfig
	Disable()
	GetReadTimeout() int64
	IsEnabled() bool
	SetReadTimeout(int)
}

type BaseSubDomainRunner struct {
	httpClient       *RewriteTimeoutHTTPClient
	dnsClient        *dns.Client
	config           SubDomainConfig
	logger           *log.Logger
	connectionConfig *utils.ConnectionConfig
	geodbClient      *geodb.Client
}

type SubDomainRunner interface {
	Config() SubDomainConfig
	Init(*RewriteTimeoutHTTPClient, *dns.Client, SubDomainConfig, *utils.ConnectionConfig, *log.Logger, *geodb.Client)
	Meta() *model.SourceMeta
	New() SubDomainRunner
	Run(context.Context, *model.SubDomainResult) ([]*model.SubDomainResult, error)
	RunChan(context.Context, *model.SubDomainResult, interface{}) (chan *model.SubDomainResult, error)
}
type httpfinder struct {
	BaseSubDomainRunner
	jsSet     mapset.Set
	domainSet mapset.Set
	once      sync.Once
}
