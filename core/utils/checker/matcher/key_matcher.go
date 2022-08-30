/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package matcher

import "sync"

type KeyMatcher struct {
	inserted bool
	sync.Map
}
