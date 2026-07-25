/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package cmd_injection

import "wscan/core/plugins/helper/expr"

type CMDInjectionPayload struct {
	payloadExpr *expr.Expr
}

func (p *CMDInjectionPayload) Render(data string) (string, string) {
	p.payloadExpr.Render(data)
	return "", ""
}
