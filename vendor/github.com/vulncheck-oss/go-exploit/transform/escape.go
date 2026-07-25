package transform

import (
	"encoding/xml"
	"html"
	"strings"

	"github.com/vulncheck-oss/go-exploit/output"
)

var EscapeHTML = html.EscapeString

func EscapeXML(s string) string {
	var escaped strings.Builder

	err := xml.EscapeText(&escaped, []byte(s))
	if err != nil {
		output.PrintFrameworkError(err.Error())

		return ""
	}

	return escaped.String()
}
