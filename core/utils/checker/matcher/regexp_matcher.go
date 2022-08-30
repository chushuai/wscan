/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package matcher

import (
	"regexp"
)

type RegexpMatcher struct {
	regexps []*regexp.Regexp
}
