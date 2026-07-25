/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package bruteforce

import (
	"context"
	"sync"
	"time"
	"wscan/core/plugins/base"
	"wscan/core/utils"
	logger "wscan/core/utils/log"

	"golang.org/x/time/rate"
)

type CommonConfig struct {
	BruteTimeout              int64   `json:"-" yaml:"-"`
	MaxBruteTimes             int32   `json:"-" yaml:"-"`
	DialTimeout               int64   `json:"-" yaml:"-"`
	ReadTimeout               int64   `json:"-" yaml:"-"`
	MaxContinuousBruteTimes   int32   `json:"-" yaml:"-"`
	ContinuousBruteInterval   int64   `json:"-" yaml:"-"`
	QPS                       float64 `json:"-" yaml:"-"`
	DisableEmbeddedDictionary bool    `json:"-" yaml:"-"`
}

type Config struct {
	base.PluginBaseConfig   `json:",inline" yaml:",inline"`
	UsernameDictionary      string `json:"username_dictionary" yaml:"username_dictionary" #:"自定义用户名字典, 为空将使用内置 TOP10, 配置后将与内置字典**合并**"`
	PasswordDictionary      string `json:"password_dictionary" yaml:"password_dictionary" #:"自定义密码字典，为空将使用内置 TOP100, 配置后将与内置字典**合并**"`
	DetectDefaultPassword   bool   `json:"-" yaml:"-"`
	DetectUnsafeLoginMethod bool   `json:"-" yaml:"-"`
	*CommonConfig           `json:"-" yaml:"-"`
	SingleConfigMap         map[int]Configure `json:"-" yaml:"-"`
}

// BaseConfig 返回基本配置, 固定格式, 无需修改
func (c *Config) BaseConfig() *base.PluginBaseConfig {
	return &c.PluginBaseConfig
}

type BruteForce struct {
	base.PluginMixinInitConfig
	base.PluginMixinClose
	usernames       []string
	passwords       []string
	dictionaryMap   map[string][]byte
	singleConfigMap map[int]Configure
	*CommonConfig
}

type Clonable interface {
	Clone() any
}

type CommonConfigure interface {
	GetBruteTimeout() int64
	GetContinuousBruteInterval() int64
	GetDialTimeout() int64
	GetDisableEmbeddedDictionary() bool
	GetMaxBruteTimes() int32
	GetMaxContinuousBruteTimes() int32
	GetQPS() float64
	GetReadTimeout() int64
	SetBruteTimeout(int64)
	SetContinuousBruteInterval(int64)
	SetDialTimeout(int64)
	SetDisableEmbeddedDictionary(bool)
	SetMaxBruteTimes(int32)
	SetMaxContinuousBruteTimes(int32)
	SetQPS(float64)
	SetReadTimeout(int64)
}

type Configure interface {
	CommonConfigure
	GetPasswordDictionary() string
	GetUsernameDictionary() string
	SetPasswordDictionary(string)
	SetUsernameDictionary(string)
}

type Initializable interface {
	Init(context.Context, int, *BruteForce, *base.ApolloBase)
}

type dictionaryLoader struct {
	bb *base.ApolloBase
}

func (*BruteForce) Close() error {
	return nil
}

func (*BruteForce) DefaultConfig() base.PluginConfigInterface {
	config := &Config{PluginBaseConfig: base.PluginBaseConfig{
		Name:    "brute-force",
		Enabled: true,
	}}
	config.CommonConfig = &CommonConfig{}
	return config
}

func (p *BruteForce) Fingers() []*base.Finger {
	fingers := []*base.Finger{}
	ba := basicAuth{
		bf: p,
	}
	fb := formBrute{
		bf: p,
	}
	fingers = append(fingers, ba.Finger())
	fingers = append(fingers, fb.Finger())
	return fingers
}

func (p *BruteForce) GetConfig() base.PluginConfigInterface {
	return p.PluginMixinInitConfig.GetConfig()
}

func (p *BruteForce) Init(ctx context.Context, pci base.PluginConfigInterface, ab *base.ApolloBase) error {
	logger.Debug("BruteForce init")
	p.PluginMixinInitConfig.Init(ctx, pci, ab)
	c := p.GetConfig().(*Config)
	c.DialTimeout = 10
	if c.UsernameDictionary != "" {
		p.usernames = utils.ReadingLines(c.UsernameDictionary)
	}
	if c.PasswordDictionary != "" {
		p.passwords = utils.ReadingLines(c.PasswordDictionary)
	}
	users, passwords := LoadBuiltinUserPass()

	p.usernames = append(p.usernames, users...)
	p.passwords = append(p.passwords, passwords...)
	p.usernames = utils.FilterUniqueStrings(p.usernames)
	p.passwords = utils.FilterUniqueStrings(p.passwords)
	return nil
}

func (p *BruteForce) singlePassChan(count int, passes []string) (<-chan string, chan struct{}) {
	singlePassChan := make(chan string)
	stopChan := make(chan struct{})
	// 启动一个 goroutine 来生成用户名和密码组合
	go func() {
		defer close(singlePassChan)
		select {
		case <-stopChan:
			break
		default:
			for _, pass := range passes {
				select {
				case <-stopChan:
					return
				case singlePassChan <- pass:
				}
			}
		}
	}()
	return singlePassChan, stopChan
}

func (p *BruteForce) singleTokenChan(string, []string) (<-chan string, chan struct{}) {
	return nil, nil
}

func (p *BruteForce) userPassChan(count int, users []string, passes []string) (<-chan *[2]string, chan struct{}) {
	userPassChan := make(chan *[2]string)
	stopChan := make(chan struct{})
	// 启动一个 goroutine 来生成用户名和密码组合
	go func() {
		defer close(userPassChan)
		select {
		case <-stopChan:
			break
		default:
			for _, user := range users {
				for _, pass := range passes {
					select {
					case <-stopChan:
						return
					case userPassChan <- &[2]string{user, pass}:
					}
				}
			}
		}
	}()
	return userPassChan, stopChan
}

func (p *BruteForce) Clone() any {
	return nil
}
func (p *BruteForce) GetBruteTimeout() int64 {
	return p.BruteTimeout
}
func (p *BruteForce) GetContinuousBruteInterval() int64 {
	return p.ContinuousBruteInterval
}
func (p *BruteForce) GetDialTimeout() int64 {
	return p.DialTimeout
}
func (BruteForce) GetDisableEmbeddedDictionary() bool {
	return false
}
func (p *BruteForce) GetMaxBruteTimes() int32 {
	return p.MaxBruteTimes
}
func (p *BruteForce) GetMaxContinuousBruteTimes() int32 {
	return p.MaxContinuousBruteTimes
}
func (p *BruteForce) GetQPS() float64 {
	return p.QPS
}
func (p *BruteForce) GetReadTimeout() int64 {
	return p.ReadTimeout
}
func (p *BruteForce) SetBruteTimeout(bruteTimeout int64) {
	p.BruteTimeout = bruteTimeout
}
func (p *BruteForce) SetContinuousBruteInterval(continuousBruteInterval int64) {
	p.ContinuousBruteInterval = continuousBruteInterval
}
func (p *BruteForce) SetDialTimeout(dialTimeout int64) {
	p.DialTimeout = dialTimeout
}
func (BruteForce) SetDisableEmbeddedDictionary(bool) {

}
func (p *BruteForce) SetMaxBruteTimes(maxBruteTimes int32) {
	p.MaxBruteTimes = maxBruteTimes
}
func (BruteForce) SetMaxContinuousBruteTimes(int32) {

}
func (p *BruteForce) SetQPS(qps float64) {
	p.QPS = qps
}
func (p *BruteForce) SetReadTimeout(readTimeout int64) {
	p.ReadTimeout = readTimeout
}

type PluginConfig struct {
	CommonConfigure
	ctx                            context.Context
	cancel                         func()
	mut                            sync.Mutex
	limiter                        *rate.Limiter
	ticker                         *time.Ticker
	enableMaxBruteTime             bool
	enableContinuousBruteFrequency bool
	actualMaxBruteTimes            int32
	actualContinuousBruteTimes     int32
}

func (p *PluginConfig) GetBruteTimeout() int64 {
	return 1000
}
func (p *PluginConfig) GetContinuousBruteInterval() int64 {
	return 0
}
func (PluginConfig) GetDialTimeout() int64 {
	return 0
}
func (PluginConfig) GetDisableEmbeddedDictionary() bool {
	return false
}
func (PluginConfig) GetMaxBruteTimes() int32 {
	return 0
}
func (PluginConfig) GetMaxContinuousBruteTimes() int32 {
	return 0
}
func (PluginConfig) GetQPS() float64 {
	return 0
}
func (PluginConfig) GetReadTimeout() int64 {
	return 0
}
func (PluginConfig) SetBruteTimeout(int64) {

}
func (PluginConfig) SetContinuousBruteInterval(int64) {

}
func (PluginConfig) SetDialTimeout(int64) {

}
func (PluginConfig) SetDisableEmbeddedDictionary(bool) {

}
func (PluginConfig) SetMaxBruteTimes(int32) {

}
func (PluginConfig) SetMaxContinuousBruteTimes(int32) {

}
func (PluginConfig) SetQPS(float64) {

}
func (PluginConfig) SetReadTimeout(int64) {

}
