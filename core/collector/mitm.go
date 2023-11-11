/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package collector

import (
	"context"
	"github.com/panjf2000/ants/v2"
	"net"
	"wscan/core/collector/mitmhelper"
	vhttp "wscan/core/http"
	"wscan/core/resource"
	"wscan/core/utils/checker"
	logger "wscan/core/utils/log"

	_ "github.com/google/martian/log"
	"github.com/google/martian/v3"
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
	return &MitmProxy{
		conf:     conf,
		httpOpts: httpOpts,
		proxy:    martian.NewProxy(),
	}
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

	//	if x509c != nil && priv != nil {
	//
	//		mc, err := mitm.NewConfig(x509c, priv)
	//		if err != nil {
	//			//log.Fatal(err)
	//		}
	//
	//		mc.SetValidity(*validity)
	//		mc.SetOrganization(*organization)
	//		mc.SkipTLSVerify(*skipTLSVerify)
	//
	//		p.SetMITM(mc)
	//
	//		// Expose certificate authority.
	//
	//		ah := martianhttp.NewAuthorityHandler(x509c)
	//		configure("/authority.cer", ah, mux)
	//
	//		// Start TLS listener for transparent MITM.
	//		tl, err := net.Listen("tcp", *tlsAddr)
	//		if err != nil {
	//			//log.Fatal(err)
	//		}
	//
	//		go p.Serve(tls.NewListener(tl, mc.TLS()))
	//	}
	//

	return nil, nil
}
func (*MitmProxy) OnFlow(func(*vhttp.Flow) error) {

}
func (*MitmProxy) buildModifier() {

}
func (*MitmProxy) loadCerts() {

}
func (m *MitmProxy) makeResultChan() chan resource.Resource {
	return make(chan resource.Resource, 1000)
}

func init() {
}
