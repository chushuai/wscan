/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package expr

type CustomInt struct {
}

func (c *CustomInt) GetPosition() int {
	return 0
}

func (c *CustomInt) Value(string) (string, error) {
	return "", nil
}
