/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package expr

type OriginNumberToExpr struct {
}

func (*OriginNumberToExpr) GetPosition() int {
	return 0
}
func (*OriginNumberToExpr) Value(string) (string, error) {
	return "", nil
}
