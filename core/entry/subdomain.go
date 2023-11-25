/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package entry

import "wscan/core/subdomain"

func subDomainScanAction() {

}

type SubdomainConfig struct {
	subdomain.Config `json:",inline" yaml:",inline"`
	Sources          map[string]map[string]interface{} `json:"sources" yaml:"sources"`
}

func (*SubdomainConfig) WroteBack() error {
	return nil
}
