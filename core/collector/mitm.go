/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package collector

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"github.com/google/martian/v3"
	"github.com/google/martian/v3/mitm"
	"github.com/panjf2000/ants/v2"
	"io/ioutil"
	"log"
	"net"
	"os"
	"time"
	"wscan/core/collector/mitmhelper"
	vhttp "wscan/core/http"
	"wscan/core/resource"
	"wscan/core/utils"
	"wscan/core/utils/checker"
	logger "wscan/core/utils/log"
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
		conf:     conf,
		httpOpts: httpOpts,
		proxy:    martian.NewProxy(),
	}
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
	if utils.FileExists(m.conf.CACert) == false || utils.FileExists(m.conf.CACert) == false {
		utils.GenerateCAToPath("." + string(os.PathSeparator))
	}
	certPEMBlock, err = ioutil.ReadFile(m.conf.CACert)
	if err != nil {
		logger.Fatalf("CACert: %s", err)
	}
	keyPEMBlock, err = ioutil.ReadFile(m.conf.CAKey)
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
	mc.SetValidity(24 * 30 * time.Hour)
	mc.SetOrganization("Wscan Scanner")
	mc.SkipTLSVerify(true)

	m.proxy.SetMITM(mc)

}
func (m *MitmProxy) makeResultChan() chan resource.Resource {
	return make(chan resource.Resource, 1000)
}

func init() {
}
