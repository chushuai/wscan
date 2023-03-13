/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package matcher

import "testing"

func TestGlobMatcher(t *testing.T) {
	matcher := NewGlobMatcher()

	if matcher.IsEmpty() != true {
		t.Errorf("expected matcher to be empty")
	}

	err := matcher.Add([]string{"*foo*", "*bar*"})
	if err != nil {
		t.Errorf("expected no error, but got %v", err)
	}

	if matcher.IsEmpty() != false {
		t.Errorf("expected matcher to not be empty")
	}

	matches := []string{"hello foo", "world bar"}
	for _, match := range matches {
		if !matcher.Match(match) {
			t.Errorf("expected match for %s", match)
		}
	}

	nonMatches := []string{"foo bar", "baz qux"}
	for _, nonMatch := range nonMatches {
		if matcher.Match(nonMatch) {
			t.Errorf("expected no match for %s", nonMatch)
		}
	}
}
