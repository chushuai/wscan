package crawler

import (
	"bytes"
	gohttp "net/http"
	"net/url"
	"testing"

	whttp "wscan/core/http"

	"github.com/PuerkitoBio/goquery"
)

// ---------- headerContentLocationParser tests ----------

func TestHeaderContentLocationParserEmpty(t *testing.T) {
	u, _ := url.Parse("http://example.com/page")
	wu := whttp.URL{URL: *u}
	doc, _ := goquery.NewDocumentFromReader(bytes.NewReader([]byte("<html></html>")))
	resp := &whttp.Response{
		NativeResponse: &gohttp.Response{
			Header: gohttp.Header{},
		},
	}

	// Should not panic when Content-Location is empty
	headerContentLocationParser(&wu, doc, resp)
}

func TestHeaderContentLocationParserWithHeader(t *testing.T) {
	u, _ := url.Parse("http://example.com/page")
	wu := whttp.URL{URL: *u}
	doc, _ := goquery.NewDocumentFromReader(bytes.NewReader([]byte("<html></html>")))
	resp := &whttp.Response{
		NativeResponse: &gohttp.Response{
			Header: gohttp.Header{
				"Content-Location": []string{"/new-page"},
			},
		},
	}

	// Should parse Content-Location without panic
	headerContentLocationParser(&wu, doc, resp)
}

func TestHeaderContentLocationParserAbsoluteURL(t *testing.T) {
	u, _ := url.Parse("http://example.com/page")
	wu := whttp.URL{URL: *u}
	doc, _ := goquery.NewDocumentFromReader(bytes.NewReader([]byte("<html></html>")))
	resp := &whttp.Response{
		NativeResponse: &gohttp.Response{
			Header: gohttp.Header{
				"Content-Location": []string{"http://other.com/resource"},
			},
		},
	}

	headerContentLocationParser(&wu, doc, resp)
}

// ---------- ParsePKCS12 tests ----------

func TestParsePKCS12InvalidData(t *testing.T) {
	_, err := ParsePKCS12([]byte("not-valid-p12-data"), "")
	if err == nil {
		t.Error("ParsePKCS12 should return error for invalid data")
	}
}

func TestParsePKCS12EmptyData(t *testing.T) {
	_, err := ParsePKCS12([]byte{}, "")
	if err == nil {
		t.Error("ParsePKCS12 should return error for empty data")
	}
}

func TestParsePKCS12NilData(t *testing.T) {
	_, err := ParsePKCS12(nil, "password")
	if err == nil {
		t.Error("ParsePKCS12 should return error for nil data")
	}
}
