/**
2 * @Author: shaochuyu
3 * @Date: 7/6/24
4 */

package plugins

import (
	"fmt"
	"testing"
)

func TestAll(t *testing.T) {
	plugins := All()
	for _, plugin := range plugins {
		// Skip plugins that need Init before Fingers can be called
		cfg := plugin.DefaultConfig()
		if cfg == nil {
			continue
		}
		fingers := plugin.Fingers()
		for _, fp := range fingers {
			if fp != nil {
				fmt.Println(fp.Channel)
			}
		}
	}
}
