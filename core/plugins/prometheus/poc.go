/**
2 * @Author: shaochuyu
3 * @Date: 6/25/23
4 */

package prometheus

import "gopkg.in/yaml.v2"

var ORDER = 0

// 参考 pocassist/blob/master/poc/rule/rule.go
// 单个规则
type Rule struct {
	Request    RuleRequest   `yaml:"request"`
	Expression string        `yaml:"expression"`
	Output     yaml.MapSlice `yaml:"output"`
	order      int
}

type ruleAlias struct {
	Request    RuleRequest   `yaml:"request"`
	Expression string        `yaml:"expression"`
	Output     yaml.MapSlice `yaml:"output"`
}

// 用于帮助yaml解析，保证Rule有序
type RuleMapItem struct {
	Key   string
	Value Rule
}

// 用于帮助yaml解析，保证Rule有序
type RuleMapSlice []RuleMapItem

type RuleRequest struct {
	Cache           bool              `yaml:"cache"`
	Method          string            `yaml:"method"`
	Path            string            `yaml:"path"`
	Headers         map[string]string `yaml:"headers"`
	Body            string            `yaml:"body"`
	FollowRedirects bool              `yaml:"follow_redirects"`
	Content         string            `yaml:"content"`
	ReadTimeout     string            `yaml:"read_timeout"`
	ConnectionID    string            `yaml:"connection_id"`
}

type Info struct {
	Type       string `yaml:"type,omitempty"`
	ID         string `yaml:"id,omitempty"`
	Name       string `yaml:"name,omitempty"`
	Version    string `yaml:"version,omitempty"`
	Confidence int32  `yaml:"confidence,omitempty"`
}

type HostInfo struct {
	Hostname string `yaml:"hostname"`
}

type Vulnerability struct {
	ID    string         `yaml:"id,omitempty"`
	Match string         `yaml:"match,omitempty"`
	Extra map[string]any `yaml:",inline"`
}

type Fingerprint struct {
	Infos    []*Info   `yaml:"infos"`
	HostInfo *HostInfo `yaml:"host_info,omitempty"`
}

type Detail struct {
	Author        string         `yaml:"author,omitempty"`
	Links         []string       `yaml:"links,omitempty"`
	Fingerprint   *Fingerprint   `yaml:"fingerprint,omitempty"`
	Vulnerability *Vulnerability `yaml:"vulnerability,omitempty"`
	Extra         map[string]any `yaml:",inline"`
	Description   string         `yaml:"description"`
	Version       string         `yaml:"version"`
	Tags          string         `yaml:"tags"`
}

type SetMapSlice = yaml.MapSlice
type PayloadsMapSlice = yaml.MapSlice

type Payloads struct {
	Continue bool             `yaml:"continue,omitempty"`
	Payloads PayloadsMapSlice `yaml:"payloads"`
}

type Poc struct {
	Name       string       `yaml:"name"`
	Manual     bool         `default:"true" yaml:"manual"`
	Transport  string       `yaml:"transport"`
	Set        SetMapSlice  `yaml:"set"`
	Payloads   Payloads     `yaml:"payloads"`
	Rules      RuleMapSlice `yaml:"rules"`
	Expression string       `yaml:"expression"`
	Detail     Detail       `yaml:"detail"`
}

func (r *Rule) UnmarshalYAML(unmarshal func(any) error) error {
	var tmp ruleAlias
	if err := unmarshal(&tmp); err != nil {
		return err
	}

	r.Request = tmp.Request
	r.Expression = tmp.Expression
	r.Output = tmp.Output
	r.order = ORDER

	ORDER += 1

	return nil
}

func (m *RuleMapSlice) UnmarshalYAML(unmarshal func(any) error) error {
	ORDER = 0
	tempMap := make(map[string]Rule, 1)
	err := unmarshal(&tempMap)
	if err != nil {
		return err
	}

	newRuleSlice := make([]RuleMapItem, len(tempMap))

	for roleName, role := range tempMap {
		newRuleSlice[role.order] = RuleMapItem{
			Key:   roleName,
			Value: role,
		}
	}

	*m = RuleMapSlice(newRuleSlice)

	return nil
}
