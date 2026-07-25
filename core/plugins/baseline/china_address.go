/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package baseline

import (
	"context"
	"regexp"
	"wscan/core/model"
	"wscan/core/plugins/base"
)

type chinaAddress struct{}

// Chinese address patterns:
// Province + City + District + Road/Street/Building
// Common format: XX省XX市XX区XX路XX号 or XX市XX区XX街XX号
var (
	// Full format with province
	chinaAddressFullRegex = regexp.MustCompile(
		`(?:北京|天津|上海|重庆|河北|山西|辽宁|吉林|黑龙江|江苏|浙江|安徽|福建|江西|山东|河南|湖北|湖南|广东|海南|四川|贵州|云南|陕西|甘肃|青海|台湾|内蒙古|广西|西藏|宁夏|新疆)` +
			`(?:省|市|自治区|特别行政区)?` +
			`[\x{4e00}-\x{9fff}]{1,6}` +
			`(?:市|地区|州|盟)` +
			`[\x{4e00}-\x{9fff}]{1,6}` +
			`(?:区|县|市|旗)`)

	// City-level format (common in addresses)
	chinaAddressCityRegex = regexp.MustCompile(
		`[\x{4e00}-\x{9fff}]{1,6}` +
			`(?:市|区|县)` +
			`[\x{4e00}-\x{9fff}]{1,8}` +
			`(?:路|街|道|巷|弄|小区|大厦|大楼|广场|园|镇|乡)`)

	// Street/road with number
	chinaAddressStreetRegex = regexp.MustCompile(
		`[\x{4e00}-\x{9fff}]{1,8}` +
			`(?:路|街|道|巷|弄)` +
			`[\x{4e00}-\x{9fff}]{0,4}` +
			`\d+` +
			`(?:号|栋|幢|楼|室)`)
)

func (d *chinaAddress) Finger() *base.Finger {
	return &base.Finger{
		CheckAction: func(ctx context.Context, a *base.Apollo) error {
			flow := a.GetTargetFlow()
			// Skip non-text responses
			if flow.Response.IsJavaScript() || flow.Response.IsCss() || flow.Response.IsImage() {
				return nil
			}

			body := flow.Response.Text
			if body == "" {
				return nil
			}

			// Try matching address patterns in order of specificity
			matches := chinaAddressFullRegex.FindAllString(body, -1)
			if len(matches) == 0 {
				matches = chinaAddressCityRegex.FindAllString(body, -1)
			}
			if len(matches) == 0 {
				matches = chinaAddressStreetRegex.FindAllString(body, -1)
			}

			if len(matches) > 0 {
				v := a.NewWebVuln(flow.Request, flow.Response, nil)
				if v != nil {
					v.SetTargetURL(flow.Request.URL())
					v.Payload = "china-address: " + truncateString(matches[0], 100)
					a.OutputVuln(v)
				}
			}

			return nil
		},
		Channel: "web-generic",
		Binding: &model.VulnBinding{
			ID:       "baseline/sensitive/china-address",
			Plugin:   "baseline/sensitive/china-address",
			Category: "baseline/sensitive/china-address",
			Severity: model.SeverityLow,
		},
	}
}
