/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package collector

import (
	"context"
	"github.com/panjf2000/ants/v2"
	vhttp "wscan/core/assassin/http"
	"wscan/core/assassin/resource"
	"wscan/core/utils/checker"

	// "github.com/google/martian/log"
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

func NewMitmProxy() {

}

func (*MitmProxy) FitOut(context.Context, []string) (chan resource.Resource, error) {
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

//// PassiveProxy
//type PassiveProxy struct {
//	//bodyLogging     func(*http.Response) bool
//	postDataLogging        func(*http.Request) bool
//	mu                     sync.Mutex
//	Taskid                 int //发送到特定任务去扫描
//	CommunicationSingleton chan map[string]interface{}
//	HttpsCert              string
//	HttpsCertKey           string
//}
//
//// PostDataLogging returns an option that configures request post data logging.
//// func PostDataLogging(enabled bool) Option {
//// 	return func(l *Logger) {
//// 		l.postDataLogging = func(*http.Request) bool {
//// 			return enabled
//// 		}
//// 	}
//// }
//
//func NewPassiveProxy() *PassiveProxy {
//	p := &PassiveProxy{}
//	p.CommunicationSingleton = make(chan map[string]interface{})
//	return p
//}
//
//// ModifyRequest 过滤请求消息，跟据从请求发送消息
//func (p *PassiveProxy) ModifyRequest(req *http.Request) error {
//	ctx := martian.NewContext(req)
//	if ctx.SkippingLogging() {
//		return nil
//	}
//
//	id := ctx.ID()
//
//	return p.RecordRequest(id, req)
//}
//
//func postData(req *http.Request, logBody bool) (*vhttp.Variations, error) {
//	// If the request has no body (no Content-Length and Transfer-Encoding isn't
//	// chunked), skip the post data.
//	if req.ContentLength <= 0 && len(req.TransferEncoding) == 0 {
//		return nil, nil
//	}
//
//	ct := req.Header.Get("Content-Type")
//	mt, ps, err := mime.ParseMediaType(ct)
//	if err != nil {
//		//log.Errorf("har: cannot parse Content-Type header %q: %v", ct, err)
//		mt = ct
//	}
//
//	pd := &vhttp.Variations{
//		MimeType: mt,
//		Params:   []vhttp.Param{},
//	}
//
//	if !logBody {
//		return pd, nil
//	}
//
//	mv := messageview.New()
//	if err := mv.SnapshotRequest(req); err != nil {
//		return nil, err
//	}
//
//	br, err := mv.BodyReader()
//	if err != nil {
//		return nil, err
//	}
//
//	body, err := ioutil.ReadAll(br)
//	if err != nil {
//		return nil, err
//	}
//
//	pd.Text = string(body)
//
//	switch mt {
//	case "multipart/form-data":
//		mpr := multipart.NewReader(br, ps["boundary"])
//
//		for {
//			p, err := mpr.NextPart()
//			if err == io.EOF {
//				break
//			}
//			if err != nil {
//				return nil, err
//			}
//			defer p.Close()
//
//			body, err := ioutil.ReadAll(p)
//			if err != nil {
//				return nil, err
//			}
//
//			pd.Params = append(pd.Params, vhttp.Param{
//				Name:        p.FormName(),
//				Filename:    p.FileName(),
//				ContentType: p.Header.Get("Content-Type"),
//				Value:       string(body),
//			})
//		}
//	case "application/x-www-form-urlencoded":
//		body, err := ioutil.ReadAll(br)
//		if err != nil {
//			return nil, err
//		}
//
//		vs, err := url.ParseQuery(string(body))
//		if err != nil {
//			return nil, err
//		}
//
//		for n, vs := range vs {
//			for _, v := range vs {
//				pd.Params = append(pd.Params, vhttp.Param{
//					Name:  n,
//					Value: v,
//				})
//			}
//		}
//
//		// default:
//		// 	body, err := ioutil.ReadAll(br)
//		// 	if err != nil {
//		// 		return nil, err
//		// 	}
//
//		// 	pd.Text = string(body)
//	}
//
//	return pd, nil
//}
//
//func headers(hs http.Header) []http2.Header {
//	hhs := make([]http2.Header, 0, len(hs))
//
//	for n, vs := range hs {
//		for _, v := range vs {
//			hhs = append(hhs, http2.Header{
//				Name:  n,
//				Value: v,
//			})
//		}
//	}
//
//	return hhs
//}
//
//func cookies(cs []*http.Cookie) []vhttp.Cookie {
//	hcs := make([]vhttp.Cookie, 0, len(cs))
//
//	for _, c := range cs {
//		var expires string
//		if !c.Expires.IsZero() {
//			expires = c.Expires.Format(time.RFC3339)
//		}
//
//		hcs = append(hcs, vhttp.Cookie{
//			Name:        c.Name,
//			Value:       c.Value,
//			Path:        c.Path,
//			Domain:      c.Domain,
//			HTTPOnly:    c.HttpOnly,
//			Secure:      c.Secure,
//			Expires:     c.Expires,
//			Expires8601: expires,
//		})
//	}
//
//	return hcs
//}
//
//// NewRequest constructs and returns a Request from req. If withBody is true,
//// req.Body is read to EOF and replaced with a copy in a bytes.Buffer. An error
//// is returned (and req.Body may be in an intermediate state) if an error is
//// returned from req.Body.Read.
//func NewRequest(req *http.Request, withBody bool) (*vhttp.Request, error) {
//
//	r := &vhttp.Request{
//		Method:      req.Method,
//		URL:         req.URL.String(),
//		HTTPVersion: req.Proto,
//		HeadersSize: -1,
//		BodySize:    req.ContentLength,
//		QueryString: []vhttp.QueryString{},
//		Headers:     headers(proxyutil.RequestHeader(req).Map()),
//		Cookies:     cookies(req.Cookies()),
//	}
//
//	for n, vs := range req.URL.Query() {
//		for _, v := range vs {
//			r.QueryString = append(r.QueryString, vhttp.QueryString{
//				Name:  n,
//				Value: v,
//			})
//		}
//	}
//
//	pd, err := postData(req, withBody)
//	if err != nil {
//		return nil, err
//	}
//	r.PostData = pd
//
//	return r, nil
//}
//
//// RecordRequest logs the HTTP request with the given ID. The ID should be unique
//// per request/response pair.
//func (p *PassiveProxy) RecordRequest(id string, req *http.Request) error {
//	var postdata string
//	hreq, err := NewRequest(req, true)
//	if err != nil {
//		return err
//	}
//	headers, err := vhttp.ConvertHeadersinterface(hreq.Headers)
//	if err != nil {
//		return err
//	}
//	url := hreq.URL
//
//	if hreq.PostData != nil {
//		postdata = hreq.PostData.Text
//	}
//
//	//contenttype := hreq.PostData.MimeType
//
//	method := hreq.Method
//
//	ReqList := make(map[string]interface{})
//
//	element := make(map[string]interface{})
//	element["url"] = url
//	element["method"] = method
//	element["headers"] = headers
//	element["data"] = postdata
//	element["source"] = "agent"
//	element["hostid"] = int64(122)
//	ex := []interface{}{
//		element,
//	}
//	ReqList["agent"] = ex
//
//	p.CommunicationSingleton <- ReqList
//	return nil
//}
//
//type SProxy struct {
//	Port         int
//	CallbackFunc SProxyCallback
//}
//
//type SProxyCallback func(args interface{})
//
//var Cert string
//var PrivateKey string
//
//var (
//	en      = flag.Bool("passiveproxy", true, "start proxy")
//	addr    = flag.String("addr", ":8080", "host:port of the proxy")
//	apiAddr = flag.String("api-addr", ":8181", "host:port of the configuration API")
//	tlsAddr = flag.String("tls-addr", ":4443", "host:port of the proxy over TLS")
//	api     = flag.String("api", "martian.proxy", "hostname for the API")
//	//generateCA   = flag.Bool("generate-ca-cert", false, "generate CA certificate and private key for MITM")
//	//cert         = flag.String("cert", "", "filepath to the CA certificate used to sign MITM certificates")
//	//key          = flag.String("key", "", "filepath to the private key of the CA used to sign MITM certificates")
//	organization = flag.String("organization", "Martian Proxy", "organization name for MITM certificates")
//	validity     = flag.Duration("validity", time.Hour, "window of time that MITM certificates are valid")
//	allowCORS    = flag.Bool("cors", false, "allow CORS requests to configure the proxy")
//	//harLogging     = flag.Bool("har", true, "enable HAR logging API")
//	//marblLogging   = flag.Bool("marbl", false, "enable MARBL logging API")
//	//trafficShaping = flag.Bool("traffic-shaping", false, "enable traffic shaping API")
//	skipTLSVerify = flag.Bool("skip-tls-verify", false, "skip TLS server verification; insecure")
//	dsProxyURL    = flag.String("downstream-proxy-url", "", "URL of downstream proxy")
//)
//
//func configure(pattern string, handler http.Handler, mux *http.ServeMux) {
//	if *allowCORS {
//		handler = cors.NewHandler(handler)
//	}
//	// register handler for martian.proxy to be forwarded to
//	// local API server
//	mux.Handle(path.Join(*api, pattern), handler)
//
//	// register handler for local API server
//	p := path.Join("localhost"+*apiAddr, pattern)
//
//	mux.Handle(p, handler)
//}
//
//func (s *SProxy) Run() error {
//	//martian.Init()
//	//mlog.SetLevel(0)
//	p := martian.NewProxy()
//	defer p.Close()
//
//	l, err := net.Listen("tcp", *addr)
//	if err != nil {
//		//log.Fatal(err)
//	}
//
//	lAPI, err := net.Listen("tcp", *apiAddr)
//	if err != nil {
//		//log.Fatal(err)
//	}
//
//	//log.Printf("martian: starting proxy on %s and api on %s", l.Addr().String(), lAPI.Addr().String())
//
//	tr := &http.Transport{
//		Dial: (&net.Dialer{
//			Timeout:   30 * time.Second,
//			KeepAlive: 30 * time.Second,
//		}).Dial,
//		TLSHandshakeTimeout:   10 * time.Second,
//		ExpectContinueTimeout: time.Second,
//		TLSClientConfig: &tls.Config{
//			InsecureSkipVerify: *skipTLSVerify,
//		},
//	}
//	p.SetRoundTripper(tr)
//
//	if *dsProxyURL != "" {
//		u, err := url.Parse(*dsProxyURL)
//		if err != nil {
//			//log.Fatal(err)
//		}
//		p.SetDownstreamProxy(u)
//	}
//
//	mux := http.NewServeMux()
//
//	var x509c *x509.Certificate
//	var priv interface{}
//
//	if GenerateCA {
//		var err error
//
//		x509c, priv, err = mitm.NewAuthority("martian.proxy", "Martian Authority", 365*24*time.Hour)
//		if err != nil {
//			//log.Fatal(err)
//		}
//
//		//保存公钥私钥到当前目录上
//		certOut, _ := os.Create("./server.pem")
//		pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: x509c.Raw})
//		certOut.Close()
//
//		keyOut, _ := os.Create("./server.key")
//		pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv.(*rsa.PrivateKey))})
//		keyOut.Close()
//
//		//logger.Info("The Complete from Generating Certificat ")
//
//		return nil
//
//	} else if Cert != "" && PrivateKey != "" {
//
//		tlsc, err := tls.LoadX509KeyPair(Cert, PrivateKey)
//		if err != nil {
//			//log.Fatal(err)
//		}
//		priv = tlsc.PrivateKey
//
//		x509c, err = x509.ParseCertificate(tlsc.Certificate[0])
//		if err != nil {
//			//log.Fatal(err)
//		}
//	}
//
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
//	stack, fg := httpspec.NewStack("martian")
//
//	// wrap stack in a group so that we can forward API requests to the API port
//	// before the httpspec modifiers which include the via modifier which will
//	// trip loop detection
//	topg := fifo.NewGroup()
//
//	// Redirect API traffic to API server.
//	if *apiAddr != "" {
//		addrParts := strings.Split(lAPI.Addr().String(), ":")
//		apip := addrParts[len(addrParts)-1]
//		port, err := strconv.Atoi(apip)
//		if err != nil {
//			//log.Fatal(err)
//		}
//		host := strings.Join(addrParts[:len(addrParts)-1], ":")
//
//		// Forward traffic that pattern matches in http.DefaultServeMux
//		apif := servemux.NewFilter(mux)
//		apif.SetRequestModifier(mapi.NewForwarder(host, port))
//		topg.AddRequestModifier(apif)
//	}
//	topg.AddRequestModifier(stack)
//	topg.AddResponseModifier(stack)
//
//	p.SetRequestModifier(topg)
//	p.SetResponseModifier(topg)
//
//	m := martianhttp.NewModifier()
//	fg.AddRequestModifier(m)
//	fg.AddResponseModifier(m)
//
//	//////////////////////////////////////////////////////////////
//	PProxy := NewPassiveProxy()
//
//	muxf := servemux.NewFilter(mux)
//
//	muxf.RequestWhenFalse(PProxy)
//	stack.AddRequestModifier(muxf)
//
//	s.CallbackFunc(PProxy)
//
//	//////////////////////////////////////////////////////////////
//	configure("/configure", m, mux)
//
//	go p.Serve(l)
//
//	go http.Serve(lAPI, mux)
//
//	sigc := make(chan os.Signal, 1)
//	signal.Notify(sigc, os.Interrupt)
//
//	<-sigc
//
//	// log.Println("martian: shutting down")
//	os.Exit(0)
//	return nil
//}
