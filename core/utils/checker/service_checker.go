/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package checker

type ServiceCheckerConfig struct {
	HostnameAllowed    []string
	HostnameDisallowed []string
	TCPPortAllowed     []string
	TCPPortDisallowed  []string
	UDPPortAllowed     []string
	UDPPortDisallowed  []string
}
