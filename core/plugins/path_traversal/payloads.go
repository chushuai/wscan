/**
2 * @Author: shaochuyu
3 * @Date: 5/7/2022 11:30
4 */

package path_traversal

import (
	_ "embed"
	"encoding/xml"
	"regexp"
	"strings"
	logger "wscan/core/utils/log"
)

//go:embed "payload.xml"
var fileIncludeRules string

type Rule struct {
	Vector   string `xml:"vector,attr"`
	Windows  int    `xml:"windows,attr"`
	Linux    int    `xml:"linux,attr"`
	Data     string `xml:",cdata"`
	compiled *regexp.Regexp
	typ      string
}

type Rules struct {
	LFI []Rule `xml:"LFI>rule"`
	RFI []Rule `xml:"RFI>rule"`
	FI  []Rule `xml:"FI>rule"`
}

type Root struct {
	XMLName xml.Name `xml:"root"`
	LFI     []Rule   `xml:"LFI>rule"`
	RFI     []Rule   `xml:"RFI>rule"`
	FI      []Rule   `xml:"FI>rule"`
}

var (
	pathTraversalRules []Rule
)

func init() {
	var parsedRoot Root
	err := xml.Unmarshal([]byte(fileIncludeRules), &parsedRoot)
	if err != nil {
		logger.Error(err)
		return
	}

	for _, rule := range parsedRoot.LFI {
		compiled, err := regexp.Compile(strings.TrimSpace(rule.Data))
		if err != nil {
			logger.Error(err)
			return
		}
		rule.compiled = compiled
		rule.typ = "LFI"
		pathTraversalRules = append(pathTraversalRules, rule)
	}

	for _, rule := range parsedRoot.RFI {
		compiled, err := regexp.Compile(strings.TrimSpace(rule.Data))
		if err != nil {
			logger.Error(err)
			return
		}
		rule.compiled = compiled
		rule.typ = "RFI"
		pathTraversalRules = append(pathTraversalRules, rule)
	}

	for _, rule := range parsedRoot.FI {
		compiled, err := regexp.Compile(strings.TrimSpace(rule.Data))
		if err != nil {
			logger.Error(err)
			return
		}
		rule.compiled = compiled
		rule.typ = "FI"
		pathTraversalRules = append(pathTraversalRules, rule)
	}
	return
}
