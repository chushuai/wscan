/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package matcher

type PortMatcher struct {
	origin     []string
	singlePort []int
	actions    []func(int) bool
}
