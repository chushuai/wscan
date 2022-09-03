/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package fastdomain

import (
	"wscan/core/assassin/http"
	"wscan/ext/fastdomain/datasource"
	"wscan/ext/fastdomain/utils"
)

type Config struct {
	ICANNCheck        bool                                  `json:"icann_check" yaml:"icann_check" #:"校验顶级域名"`
	MaxParallel       int                                   `json:"max_parallel" yaml:"max_parallel" #:"子域名探测的并发度"`
	AllowRecursion    bool                                  `json:"allow_recursion" yaml:"allow_recursion" #:"是否允许递归探测, 开启后，扫描完一级域名后，会自动将一级的每个域名作为新的目标"`
	MaxRecursionDepth int                                   `json:"max_recursion_depth" yaml:"max_recursion_depth" #:"最大允许的递归深度, 3 表示 3 级子域名 仅当 allow_recursion 开启时才有意义"`
	WebOnly           bool                                  `json:"web_only" yaml:"web_only" #:"结果中仅显示有 web 应用的, 没有 web 应用的将被丢弃"`
	IPOnly            bool                                  `json:"ip_only" yaml:"ip_only" #:"结果中仅展示解析出 IP 的，没有解析成功的将被丢弃"`
	Servers           []string                              `json:"servers" yaml:"servers" #:"子域名扫描过程中使用的 DNS Server"`
	Sources           map[string]datasource.SubDomainConfig `json:"-" yaml:"-"`
	HTTPConfig        *http.ClientOptions                   `json:"-" yaml:"-"`
	ConnectionConfig  *utils.ConnectionConfig               `json:"-" yaml:"-"`
}
