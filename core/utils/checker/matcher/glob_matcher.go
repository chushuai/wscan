/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package matcher

import "sync"

type GlobMatcher struct {
	sync.Mutex
	pattern map[string]struct{}
	//globs   []glob.Glob
}
