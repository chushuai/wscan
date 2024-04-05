/**
2 * @Author: shaochuyu
3 * @Date: 4/4/24
4 */

package fingerprint

type FingerprintInfo struct {
	Name   string `yaml:"name"`
	Author string `yaml:"author"`
}

type FingerprintPscan struct {
	Path        []string `yaml:"path"`
	Expressions []string `yaml:"expressions"`
}

type FingerprintRule struct {
	Engine string           `yaml:"engine"`
	Info   FingerprintInfo  `yaml:"info"`
	Pscan  FingerprintPscan `yaml:"pscan"`
}

func LoadFingerprintRule(ruleFile string) (*FingerprintRule, error) {

	return nil, nil
}
