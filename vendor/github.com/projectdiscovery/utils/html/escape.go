// Package html extends the standard Go [html] package with more comprehensive
// HTML escaping capabilities.
//
// While the standard library's [html.EscapeString] only escapes a minimal set
// of characters ('<', '>', '&', ”', '"'), this package provides an [EscapeString]
// function that converts a much wider range of characters into their
// corresponding HTML named character references from the W3C specification.
// This includes support for two-codepoint composite characters and ensures all
// entities are semicolon-terminated.
//
// For convenience, aliases for the standard library's [html.EscapeString]
// ([EscapeStringStd]) and [html.UnescapeString] are also provided.
//
// A key invariant of this package is that for any string `s`,
// `UnescapeString(EscapeString(s)) == s`.
package html

import (
	"html"
	"strings"
)

// isLowercase checks if the entity name (without semicolon) starts with a
// lowercase letter
func isLowercase(name string) bool {
	if len(name) == 0 {
		return false
	}

	first := rune(name[0])

	return first >= 'a' && first <= 'z'
}

var (
	// EscapeStringStd is an alias for the standard library's [html.EscapeString],
	// which escapes only the characters <, >, &, ', and ".
	EscapeStringStd = html.EscapeString

	// UnescapeString is an alias for the standard library's [html.UnescapeString].
	UnescapeString = html.UnescapeString
)

// EscapeString escapes a wider range of HTML characters than the standard
// [html.EscapeString] function. It uses the full entity map from W3C to convert
// characters like "é" to "&eacute;" and "α" to "&alpha;". It also escapes basic
// HTML characters like "<" to "&lt;".
// EscapeString is the inverse of [UnescapeString], meaning that
// UnescapeString(EscapeString(s)) == s always holds, but the converse isn't
// always true.
func EscapeString(s string) string {
	reverseMap, entity2Map := reverseEntityMaps()

	var result strings.Builder
	runes := []rune(s)

	for i := 0; i < len(runes); i++ {
		r := runes[i]

		if i+1 < len(runes) {
			pair := [2]rune{r, runes[i+1]}
			if entityName, exists := entity2Map[pair]; exists {
				result.WriteString("&")
				result.WriteString(entityName)
				i++
				continue
			}
		}

		if entityName, exists := reverseMap[r]; exists {
			result.WriteString("&")
			result.WriteString(entityName)
		} else {
			result.WriteRune(r)
		}
	}

	return result.String()
}
