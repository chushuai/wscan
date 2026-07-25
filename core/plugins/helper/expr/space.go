/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package expr

type Space struct {
}

func (Space) GetPosition() int {
	return 0
}
func (Space) Value(string) (string, error) {
	return "", nil
}

func NewNewSpace() {

}
