package http

import (
	"strings"
	"testing"

	"github.com/antchfx/xmlquery"
)

func TestIsMeaninglessCookieKey(t *testing.T) {
	result := IsMeaninglessCookieKey()
	if result != false {
		t.Errorf("IsMeaninglessCookieKey() = %v, want false", result)
	}
}

func TestConvertValue_Integer(t *testing.T) {
	result := ConvertValue("42", "100")
	if result != "100" {
		t.Errorf("ConvertValue(integer) = %q, want %q", result, "100")
	}
}

func TestConvertValue_IntegerNegative(t *testing.T) {
	result := ConvertValue("-5", "10")
	if result != "10" {
		t.Errorf("ConvertValue(negative integer) = %q, want %q", result, "10")
	}
}

func TestConvertValue_Float(t *testing.T) {
	result := ConvertValue("3.14", "2.71")
	// Should parse 2.71 as float64 and format it
	if result == "" {
		t.Error("ConvertValue(float) should not return empty string")
	}
}

func TestConvertValue_Boolean(t *testing.T) {
	result := ConvertValue("true", "false")
	if result != "false" {
		t.Errorf("ConvertValue(bool) = %q, want %q", result, "false")
	}
}

func TestConvertValue_String(t *testing.T) {
	result := ConvertValue("hello", "world")
	if result != "world" {
		t.Errorf("ConvertValue(string) = %q, want %q", result, "world")
	}
}

func TestRecursiveXMLNode_Nil(t *testing.T) {
	// Should not panic on nil node
	RecursiveXMLNode(nil, func(node *xmlquery.Node) {})
}

func TestRecursiveXMLNode_Simple(t *testing.T) {
	doc, err := xmlquery.Parse(strings.NewReader("<root><child>text</child></root>"))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	count := 0
	RecursiveXMLNode(doc, func(node *xmlquery.Node) {
		count++
	})

	if count == 0 {
		t.Error("RecursiveXMLNode should visit at least one node")
	}
}

func TestGetXpathFromNode_Nil(t *testing.T) {
	result := GetXpathFromNode(nil)
	if result != "" {
		t.Errorf("GetXpathFromNode(nil) = %q, want empty string", result)
	}
}

func TestGetXpathFromNode_Element(t *testing.T) {
	doc, err := xmlquery.Parse(strings.NewReader("<root><child>text</child></root>"))
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}

	child := xmlquery.FindOne(doc, "//child")
	if child == nil {
		t.Fatal("could not find child element")
	}

	xpath := GetXpathFromNode(child)
	if xpath == "" {
		t.Error("GetXpathFromNode should return non-empty xpath for element node")
	}
}
