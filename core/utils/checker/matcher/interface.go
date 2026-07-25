/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package matcher

type Matcher interface {
	Add([]string) error
	IsEmpty() bool
	Match(string) bool
}
