/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package cmd_injection

import "wscan/core/plugins/helper/expr"

type TemplateInjectionPayload struct {
	payloadExpr *expr.Expr
}

func (*TemplateInjectionPayload) Render(string) (string, string) {
	return "", ""
}
