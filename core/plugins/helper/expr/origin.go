/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package expr

type Origin struct {
}

func (*Origin) GetPosition() int {
	return 0
}

func (*Origin) Value(string) (string, error) {
	return "", nil
}
