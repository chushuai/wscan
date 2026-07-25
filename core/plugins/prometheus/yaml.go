/**
2 * @Author: shaochuyu
3 * @Date: 6/27/23
4 */

package prometheus

import (
	"wscan/core/plugins/helper/expression"
)

type YamlScript struct {
	Name        string                 `yaml:"name"`
	Manual      bool                   `default:"true" yaml:"manual"`
	NeedReverse bool                   `yaml:"-"`
	Script      *Script                `yaml:",inline"`
	Detail      *Detail                `yaml:"detail"`
	Exp         *expression.Expression `yaml:"-"`
}

func (YamlScript) MarshalYAML() (any, error) {
	return nil, nil
}
