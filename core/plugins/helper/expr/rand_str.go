/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package expr

type RandStr struct {
	Position int
}

func (*RandStr) GetPosition() int {
	return 0
}
func (*RandStr) Value(string) (string, error) {
	return "", nil
}
