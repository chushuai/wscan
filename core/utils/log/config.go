/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package log

type LoggerConfig struct {
	Level string
}

type Config struct {
	Level      string
	FileConfig FileConfig `json:"file_config" yaml:"file_config"`
	Loggers    map[string]LoggerConfig
}

func (*Config) Clone() *Config {
	return nil
}

type FileConfig struct {
	Dir        string
	MaxSize    int
	MaxBackUps int
	MaxAge     int
	Compress   bool
}

func NewDefaultConfig() Config {
	return Config{}
}

func SetConfig() {

}
