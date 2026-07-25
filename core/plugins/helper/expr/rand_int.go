/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package expr

type RandInt struct {
	Position int
}

func (*RandInt) GetPosition() int {
	return 0
}
func (*RandInt) Value(string) (string, error) {
	return "", nil
}
