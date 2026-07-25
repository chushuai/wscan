package comparer

import (
	"testing"

	whttp "wscan/core/http"
)

// ===== htmlToString coverage boost =====
// The error branch in htmlToString (when io.ReadAll returns error) is unreachable
// because strings.NewReader never returns errors. These tests cover the happy path
// more thoroughly and document edge cases.

func TestHtmlToString_UnicodeContent(t *testing.T) {
	resp := &whttp.Response{
		Text: "<html><body>你好世界 🌍</body></html>",
	}
	result := htmlToString(resp)
	if result != resp.Text {
		t.Errorf("htmlToString() = %q, want %q", result, resp.Text)
	}
}

func TestHtmlToString_SpecialCharacters(t *testing.T) {
	resp := &whttp.Response{
		Text: `<tag attr="value">&amp; &lt; &gt;</tag>`,
	}
	result := htmlToString(resp)
	if result != resp.Text {
		t.Errorf("htmlToString() = %q, want %q", result, resp.Text)
	}
}

func TestHtmlToString_NewlinesAndTabs(t *testing.T) {
	resp := &whttp.Response{
		Text: "line1\nline2\ttabbed\r\nwindows",
	}
	result := htmlToString(resp)
	if result != resp.Text {
		t.Errorf("htmlToString() = %q, want %q", result, resp.Text)
	}
}

func TestHtmlToString_NullBytes(t *testing.T) {
	resp := &whttp.Response{
		Text: "before\x00after",
	}
	result := htmlToString(resp)
	// strings.NewReader handles null bytes fine
	if result != resp.Text {
		t.Errorf("htmlToString() with null bytes = %q, want %q", result, resp.Text)
	}
}

func TestHtmlToString_WhitespaceOnly(t *testing.T) {
	resp := &whttp.Response{
		Text: "   \t\n  ",
	}
	result := htmlToString(resp)
	if result != resp.Text {
		t.Errorf("htmlToString() = %q, want %q", result, resp.Text)
	}
}
