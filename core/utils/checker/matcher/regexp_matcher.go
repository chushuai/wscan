/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package matcher

import (
	"fmt"
	"regexp"
)

type RegexpMatcher struct {
	regexps []*regexp.Regexp
}

func NewRegexpMatcher() *RegexpMatcher {
	return &RegexpMatcher{}
}

func (r *RegexpMatcher) Add(patterns []string) error {
	for _, p := range patterns {
		re, err := regexp.Compile(p)
		if err != nil {
			return fmt.Errorf("failed to compile regexp pattern %q: %v", p, err)
		}
		r.regexps = append(r.regexps, re)
	}
	return nil
}

func (r *RegexpMatcher) IsEmpty() bool {
	return len(r.regexps) == 0
}

func (r *RegexpMatcher) Match(s string) bool {
	for _, re := range r.regexps {
		if re.MatchString(s) {
			return true
		}
	}
	return false
}
