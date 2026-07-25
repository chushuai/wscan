/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package baseline

import (
	"wscan/core/utils/checker"
)

type cookieHTTPOnly struct {
	filter *checker.URLChecker
}

type cookiePassword struct {
	filter *checker.URLChecker
}

type cookieSecure struct {
	filter *checker.URLChecker
}
