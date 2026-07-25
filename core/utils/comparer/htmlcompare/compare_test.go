package htmlcompare

import (
	"os"
	"regexp"
	"testing"
)

func TestNewHTMLProcessorFromString(t *testing.T) {
	html := "<html><head><title>Test</title></head><body>Hello</body></html>"
	hp := NewHTMLProcessorFromString(html)
	if hp == nil {
		t.Fatal("NewHTMLProcessorFromString returned nil")
	}
}

func TestHTMLProcessor_CompareHeadWith(t *testing.T) {
	html := "<html><head><title>My Title</title></head><body>Content</body></html>"
	hp := NewHTMLProcessorFromString(html)

	if !hp.CompareHeadWith("My Title") {
		t.Error("expected to find 'My Title' in head tokens")
	}
	if hp.CompareHeadWith("NonExistent") {
		t.Error("should not find 'NonExistent' in head tokens")
	}
}

func TestHTMLProcessor_CompareHtmlWith(t *testing.T) {
	html := "<html><head><title>Test</title></head><body><div>Content</div></body></html>"
	hp := NewHTMLProcessorFromString(html)

	if !hp.CompareHtmlWith("div") {
		t.Error("expected to find 'div' in html tokens")
	}
	if hp.CompareHtmlWith("span") {
		t.Error("should not find 'span' in html tokens")
	}
}

func TestHTMLProcessor_CompareTextWith(t *testing.T) {
	html := "<html><head><title>Test</title></head><body>Hello World</body></html>"
	hp := NewHTMLProcessorFromString(html)

	if !hp.CompareTextWith("Hello World") {
		t.Error("expected to find 'Hello World' in text tokens")
	}
	if hp.CompareTextWith("Goodbye") {
		t.Error("should not find 'Goodbye' in text tokens")
	}
}

func TestHTMLProcessor_CompareWith(t *testing.T) {
	html := "<html><head><title>MyTitle</title></head><body><p>MyText</p></body></html>"
	hp := NewHTMLProcessorFromString(html)

	if !hp.CompareWith("MyTitle") {
		t.Error("expected to find 'MyTitle' via CompareWith (head)")
	}
	if !hp.CompareWith("p") {
		t.Error("expected to find 'p' via CompareWith (html)")
	}
	if !hp.CompareWith("MyText") {
		t.Error("expected to find 'MyText' via CompareWith (text)")
	}
	if hp.CompareWith("NonExistent") {
		t.Error("should not find 'NonExistent' via CompareWith")
	}
}

func TestHTMLProcessor_GetStringData(t *testing.T) {
	html := "<html><body>Hello</body></html>"
	hp := NewHTMLProcessorFromString(html)

	if hp.GetStringData() != html {
		t.Errorf("GetStringData() = %q, expected %q", hp.GetStringData(), html)
	}
}

func TestHTMLProcessor_MatchRegex(t *testing.T) {
	html := "<html><body>Hello World 123</body></html>"
	hp := NewHTMLProcessorFromString(html)

	r := regexp.MustCompile(`\d+`)
	if !hp.MatchRegex(r) {
		t.Error("expected regex to match digits in HTML")
	}

	r2 := regexp.MustCompile(`^xyz$`)
	if hp.MatchRegex(r2) {
		t.Error("regex should not match")
	}
}

func TestHTMLProcessor_ReplaceRegex(t *testing.T) {
	html := "<html><body>Hello World 123</body></html>"
	hp := NewHTMLProcessorFromString(html)

	r := regexp.MustCompile(`\d+`)
	hp.ReplaceRegex(r, "NUM")

	result := hp.GetStringData()
	if matched, _ := regexp.MatchString(`NUM`, result); !matched {
		t.Errorf("after ReplaceRegex, expected 'NUM' in result, got %q", result)
	}
}

func TestHTMLProcessor_DumpDataToFile(t *testing.T) {
	html := "<html><body>Test Content</body></html>"
	hp := NewHTMLProcessorFromString(html)

	tmpFile, err := os.CreateTemp("", "html-dump-test-*.html")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	tmpPath := tmpFile.Name()
	tmpFile.Close()
	defer os.Remove(tmpPath)

	err = hp.DumpDataToFile(tmpPath)
	if err != nil {
		t.Errorf("DumpDataToFile() returned error: %v", err)
	}

	data, err := os.ReadFile(tmpPath)
	if err != nil {
		t.Fatalf("failed to read temp file: %v", err)
	}
	if string(data) != html {
		t.Errorf("dumped data = %q, expected %q", string(data), html)
	}
}

func TestHTMLProcessor_EmptyHTML(t *testing.T) {
	hp := NewHTMLProcessorFromString("")

	if hp.CompareHeadWith("anything") {
		t.Error("empty HTML should have no head tokens")
	}
	if hp.CompareHtmlWith("anything") {
		t.Error("empty HTML should have no html tokens")
	}
	if hp.CompareTextWith("anything") {
		t.Error("empty HTML should have no text tokens")
	}
}

func TestHTMLProcessor_MultipleHeadElements(t *testing.T) {
	html := "<html><head><style>body{}</style><script>var x=1;</script><title>Test</title></head><body>Content</body></html>"
	hp := NewHTMLProcessorFromString(html)

	if !hp.CompareHeadWith("Test") {
		t.Error("expected to find 'Test' in head tokens")
	}
}

func TestHTMLProcessor_NestedElements(t *testing.T) {
	html := "<html><body><div><p><span>Nested</span></p></div></body></html>"
	hp := NewHTMLProcessorFromString(html)

	if !hp.CompareHtmlWith("div") {
		t.Error("expected to find 'div' in html tokens")
	}
	if !hp.CompareHtmlWith("p") {
		t.Error("expected to find 'p' in html tokens")
	}
	if !hp.CompareHtmlWith("span") {
		t.Error("expected to find 'span' in html tokens")
	}
	if !hp.CompareTextWith("Nested") {
		t.Error("expected to find 'Nested' in text tokens")
	}
}

func TestCompareHTMLProcessors_Identical(t *testing.T) {
	html := "<html><head><title>Test</title></head><body><p>Hello</p></body></html>"
	hp1 := NewHTMLProcessorFromString(html)
	hp2 := NewHTMLProcessorFromString(html)

	ratio := CompareHTMLProcessors(hp1, hp2)
	if ratio != 1.0 {
		t.Errorf("CompareHTMLProcessors for identical HTML = %v, expected 1.0", ratio)
	}
}

func TestCompareHTMLProcessors_Different(t *testing.T) {
	html1 := "<html><head><title>Title1</title></head><body><div>Content1</div></body></html>"
	html2 := "<html><head><title>Title2</title></head><body><span>Content2</span></body></html>"
	hp1 := NewHTMLProcessorFromString(html1)
	hp2 := NewHTMLProcessorFromString(html2)

	ratio := CompareHTMLProcessors(hp1, hp2)
	// They should not be identical
	if ratio == 1.0 {
		t.Error("CompareHTMLProcessors for different HTML should not be 1.0")
	}
}

func TestCompareHTMLProcessors_Empty(t *testing.T) {
	hp1 := NewHTMLProcessorFromString("")
	hp2 := NewHTMLProcessorFromString("")

	ratio := CompareHTMLProcessors(hp1, hp2)
	// Both empty -> all three similarities are 1.0 -> average = 1.0
	if ratio != 1.0 {
		t.Errorf("CompareHTMLProcessors for empty HTML = %v, expected 1.0", ratio)
	}
}

func TestCompareHTMLProcessors_PartialOverlap(t *testing.T) {
	html1 := "<html><head><title>Common</title></head><body><div>A</div><p>B</p></body></html>"
	html2 := "<html><head><title>Common</title></head><body><div>A</div><span>C</span></body></html>"
	hp1 := NewHTMLProcessorFromString(html1)
	hp2 := NewHTMLProcessorFromString(html2)

	ratio := CompareHTMLProcessors(hp1, hp2)
	// Should be between 0 and 1
	if ratio < 0 || ratio > 1.0 {
		t.Errorf("CompareHTMLProcessors = %v, expected between 0 and 1", ratio)
	}
}
