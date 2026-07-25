/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package collector

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"time"
	"wscan/core/collector/mitmhelper"
	vhttp "wscan/core/http"
	"wscan/core/resource"
	"wscan/core/utils"
	"wscan/core/utils/checker"
	"wscan/core/utils/checker/filter"
	logger "wscan/core/utils/log"

	"github.com/google/martian/v3"
	martianlog "github.com/google/martian/v3/log"
	"github.com/google/martian/v3/mitm"
	"github.com/panjf2000/ants/v2"
)

var GenerateCA bool

type MitmProxy struct {
	proxy      *martian.Proxy
	conf       *MitmConfig
	httpOpts   *vhttp.ClientOptions
	pool       *ants.Pool
	dupChecker *checker.RequestChecker
	onFlow     func(*vhttp.Flow) error
}

func NewMitmProxy(conf *MitmConfig, httpOpts *vhttp.ClientOptions) *MitmProxy {
	m := &MitmProxy{
		conf:       conf,
		httpOpts:   httpOpts,
		proxy:      martian.NewProxy(),
		dupChecker: checker.NewRequestChecker(conf.Restriction, &filter.SyncMapFilter{}),
	}

	pool, err := ants.NewPool(100)
	if err != nil {
		logger.Fatalf("failed to create ants pool: %v", err)
	}
	m.pool = pool
	// 创建一个 Martian 中间件栈
	m.loadCerts()
	return m
}

func (m *MitmProxy) FitOut(context.Context, []string) (chan resource.Resource, error) {
	martian.Init()
	l, err := net.Listen("tcp", m.conf.Listen)
	if err != nil {
		logger.Fatal(err)
	}
	logger.Infof("starting mitm server at %s", m.conf.Listen)
	out := m.makeResultChan()
	httpMirrorModifier := mitmhelper.NewHTTPMirrorModifier(m.pool, m.dupChecker, m.httpOpts, out)
	m.proxy.SetRequestModifier(httpMirrorModifier)
	m.proxy.SetResponseModifier(httpMirrorModifier)

	go m.proxy.Serve(l)

	return out, nil
}

func (*MitmProxy) OnFlow(func(*vhttp.Flow) error) {

}
func (*MitmProxy) buildModifier() {

}
func (m *MitmProxy) loadCerts() {
	var keyPEMBlock, certPEMBlock []byte
	var err error
	if !utils.FileExists(m.conf.CACert) || !utils.FileExists(m.conf.CACert) {
		utils.GenerateCAToPath("." + string(os.PathSeparator))
	}
	certPEMBlock, err = os.ReadFile(m.conf.CACert)
	if err != nil {
		logger.Fatalf("CACert: %s", err)
	}
	keyPEMBlock, err = os.ReadFile(m.conf.CAKey)
	if err != nil {
		logger.Fatalf("CAKey: %s", err)
	}
	tlsc, err := tls.X509KeyPair(certPEMBlock, keyPEMBlock)
	if err != nil {
		log.Fatal(err)
	}
	x509c, err := x509.ParseCertificate(tlsc.Certificate[0])
	if err != nil {
		log.Fatal(err)
	}
	mc, err := mitm.NewConfig(x509c, tlsc.PrivateKey)
	if err != nil {
		log.Fatal(err)
	}
	mc.TLS().MinVersion = tls.VersionTLS10
	mc.TLS().InsecureSkipVerify = true
	// mc.SetH2Config(&h2.Config{})
	mc.SetValidity(24 * 30 * time.Hour)
	mc.SetOrganization("Wscan Scanner")
	mc.SkipTLSVerify(true)
	martianlog.SetLevel(martianlog.Debug)
	upstreamProxyFunc := http.ProxyFromEnvironment
	if m.conf.DownstreamProxy != "" {
		proxyURL, err := url.Parse(m.conf.DownstreamProxy)
		if err == nil {
			upstreamProxyFunc = http.ProxyURL(proxyURL)
		} else {
			log.Printf("invalid upstream_proxy %q: %v", m.conf.DownstreamProxy, err)
		}
	}
	m.proxy.SetRoundTripper(&http.Transport{
		// TODO(adamtanner): This forces the http.Transport to not upgrade requests
		// to HTTP/2 in Go 1.6+. Remove this once Martian can support HTTP/2.
		TLSNextProto:          make(map[string]func(string, *tls.Conn) http.RoundTripper),
		Proxy:                 upstreamProxyFunc,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: time.Second,
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true,
		},
	})
	m.proxy.SetMITM(mc)
}
func (m *MitmProxy) makeResultChan() chan resource.Resource {
	return make(chan resource.Resource, 10000)
}
