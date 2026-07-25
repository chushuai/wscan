package baseline

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	wscan_http "wscan/core/http"
	"wscan/core/model"
	"wscan/core/plugins/base"
	"wscan/core/utils/printer"
)

func TestCSPDebug(t *testing.T) {
	u, _ := url.Parse("http://example.com/")
	netResp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader("<html><body>test</body></html>")),
		Request:    &http.Request{URL: u},
	}
	netResp.Header.Set("Content-Type", "text/html")
	netResp.Header.Set("Content-Security-Policy", "script-src *; style-src 'self'")
	resp, _ := wscan_http.ResponseFromNetHttpResponse(netResp)

	fmt.Printf("Response IsHTML: %v\n", resp.IsHTML())
	fmt.Printf("Response Content-Type: %s\n", resp.Header.Get("Content-Type"))
	fmt.Printf("Response CSP: %s\n", resp.Header.Get("Content-Security-Policy"))

	req, _ := wscan_http.NewRequest("GET", "http://example.com/", nil)
	a := base.NewApollo(&wscan_http.Flow{Request: req, Response: resp})

	r := &ContentSecurityPolicyScanRule{}
	fingers := r.Finger()
	fmt.Printf("Number of fingers: %d\n", len(fingers))

	for i, f := range fingers {
		fmt.Printf("Finger[%d]: %s\n", i, f.Binding.ID)
	}

	if len(fingers) > 3 {
		vulnFound := false
		a.ApolloBase.Output = &mockDebugPrinter{onPrint: func(v *model.Vuln) {
			vulnFound = true
		}}
		err := fingers[3].CheckAction(context.Background(), a)
		fmt.Printf("CheckAction error: %v, vulnFound: %v\n", err, vulnFound)
	}
}

type mockDebugPrinter struct {
	onPrint func(v *model.Vuln)
}

func (m *mockDebugPrinter) Print(v any) error {
	if vuln, ok := v.(*model.Vuln); ok && m.onPrint != nil {
		m.onPrint(vuln)
	}
	return nil
}

func (m *mockDebugPrinter) Close() error { return nil }

func (m *mockDebugPrinter) AddInterceptor(func(any) (any, error)) printer.Printer { return m }
