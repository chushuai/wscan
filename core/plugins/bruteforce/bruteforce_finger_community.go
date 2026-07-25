/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package bruteforce

import (
	"context"
	"wscan/core/plugins/base"
)

type PluginType int

func (*PluginType) GetConfig(ctx context.Context, a *base.Apollo) *PluginConfig {

	return nil
}

func (*dictionaryLoader) load() {

}
