/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package collector

import (
	"context"
	"fmt"
	"github.com/panjf2000/ants/v2"
	"net"
	"net/http"
	vhttp "wscan/core/http"
	"wscan/core/resource"
	"wscan/core/utils/checker"
	logger "wscan/core/utils/log"

	_ "github.com/google/martian/log"
	"github.com/google/martian/v3"
)

var GenerateCA bool

// requestModifier 是请求修改器，用于记录请求日志
type requestModifier struct{}

func (rm requestModifier) ModifyRequest(req *http.Request) error {
	logger.Infof("Received request: %s %s", req.Method, req.URL) // 记录请求方法、URL等日志信息
	return nil
}

// responseModifier 是响应修改器，用于记录响应日志
type responseModifier struct{}

func (rm responseModifier) ModifyResponse(res *http.Response) error {
	logger.Infof("Response status: %s", res.Status) // 记录响应状态码等日志信息
	return nil
}

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
	logger.Infof("starting mitm server at")
	martian.Init()

	l, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", m.conf.Listen))
	if err != nil {
		logger.Fatal(err)
	}

	m.proxy.SetRequestModifier(requestModifier{})
	m.proxy.SetResponseModifier(responseModifier{})

	fmt.Println("Proxy server is running on port 8080")

	m.proxy.Serve(l)

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
func (*MitmProxy) makeResultChan() {

}

func init() {
}
