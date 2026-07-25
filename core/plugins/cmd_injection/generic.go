/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package cmd_injection

type EchoBasedInjection interface {
	Render(string) (string, string)
}
