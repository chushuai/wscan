/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package expr

type Element interface {
	GetPosition() int
	Value(string) (string, error)
}
