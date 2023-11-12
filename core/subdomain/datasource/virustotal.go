/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package datasource

type virusTotal struct {
	BaseSubDomainRunner
}

type virusTotalResp struct {
	Links struct{ Next string }
}
