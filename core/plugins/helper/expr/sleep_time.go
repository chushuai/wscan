/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package expr

type SleepTime struct {
}

func (*SleepTime) GetPosition() int {
	return 0
}
func (*SleepTime) Value(string) (string, error) {
	return "", nil
}
