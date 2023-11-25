/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package baseline

import "wscan/core/utils/checker"

type corsAllowHTTPSDowngrade struct {
	filter *checker.URLChecker
}

type corsAnyOrigin struct {
	filter *checker.URLChecker
}

type corsNullWithCred struct {
	filter *checker.URLChecker
}

type corsReflected struct {
	filter *checker.URLChecker
}
