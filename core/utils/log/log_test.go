/**
2 * @Author: shaochuyu
3 * @Date: 9/11/22
4 */

package log

import "testing"

func TestLog(t *testing.T) {
	l := Logger{}
	l.Info("hello log")

}
