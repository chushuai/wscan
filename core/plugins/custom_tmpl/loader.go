/**
2 * @Author: shaochuyu
3 * @Date: 12/9/23
4 */

package custom_tmpl

import (
	"github.com/thoas/go-funk"
	"gopkg.in/yaml.v3"
	"os"
	"path/filepath"
	"strings"
	"wscan/core/plugins/base"
	"wscan/core/utils"
	logger "wscan/core/utils/log"
)

func LoadYamlTmpl(c *Config) (ret []base.FingerFactory) {
	pocPaths := []string{}
	for _, include := range c.IncludeTmpl {
		if pocFiles, err := filepath.Glob(include); err == nil {
			pocPaths = append(pocPaths, pocFiles...)
		} else {
			logger.Errorf("Path glob match error: " + err.Error())
		}
	}
	for _, pocFile := range pocPaths {
		// 只解析yml或yaml文件
		if strings.HasSuffix(pocFile, ".yml") || strings.HasSuffix(pocFile, ".yaml") {
			if yfs, err := LoadSingleTemplate(pocFile, c); err == nil {
				for _, yf := range yfs {
					ret = append(ret, yf)
				}
			}
		}
	}
	logger.Infof("Load [%d] YamlFinger(s),", len(ret))
	return
}

func LoadSingleTemplate(templateFile string, c *Config) ([]*YamlFinger, error) {
	if utils.FileExists(templateFile) == false {
		logger.Debugf("template file not found: '%v'", templateFile)
	}
	templatePath, err := filepath.Abs(templateFile)
	if err != nil {
		logger.Infof("Get template filepath error: %s", templateFile)
		return nil, err
	}
	logger.Debugf("Load template file: %v", templatePath)
	f, err := os.Open(templateFile)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	tmpl := &Template{}
	err = yaml.NewDecoder(f).Decode(tmpl)
	if err != nil {
		return nil, err
	}
	yamlScripts := []*YamlFinger{}

	for _, payload := range tmpl.Payloads {
		//for _, encoder := range tmpl.Encoders {
		if funk.ContainsString(tmpl.Placeholders, "URLPath") == true {
			ys := YamlFinger{
				YamlScript: &YamlScript{Payload: payload, Encoder: tmpl.Encoders,
					Placeholder: []string{"URLPath"}, Type: tmpl.Type, Channel: "web-directory"},
				cfg: c,
			}
			yamlScripts = append(yamlScripts, &ys)
		} else {
			ys := YamlFinger{
				YamlScript: &YamlScript{Payload: payload, Encoder: tmpl.Encoders, Placeholder: tmpl.Placeholders,
					Type: tmpl.Type, Channel: "web-generic"},
				cfg: c,
			}
			yamlScripts = append(yamlScripts, &ys)
		}
	}
	return yamlScripts, nil
}
