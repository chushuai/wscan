/**
* @Author: shaochuyu
* @Date: 12/9/23
 */
package waftest

import (
	"gopkg.in/yaml.v3"
	"os"
	"path/filepath"
	"strings"
	"wscan/core/plugins/base"
	"wscan/core/plugins/helper/payload/placeholder"
	logger "wscan/core/utils/log"
)

// LoadYamlTmpl 从配置中指定的路径加载所有 YAML 模板
func LoadYamlTmpl(c *Config) (ret []base.FingerFactory) {
	pocPaths := []string{}
	for _, include := range c.IncludeTmpl {
		if pocFiles, err := filepath.Glob(include); err == nil {
			pocPaths = append(pocPaths, pocFiles...)
		} else {
			logger.Errorf("Path glob match error: %v", err)
		}
	}
	for _, pocFile := range pocPaths {
		// 只解析yml或yaml文件
		if strings.HasSuffix(pocFile, ".yml") || strings.HasSuffix(pocFile, ".yaml") {
			if yfs, err := LoadSingleTemplate(pocFile, c); err == nil {
				for _, yf := range yfs {
					ret = append(ret, yf)
				}
			} else {
				logger.Debugf("Load template %s error: %v", pocFile, err)
			}
		}
	}
	logger.Infof("Load [%d] YamlFinger(s)", len(ret))
	return
}

// parsePlaceholderSpec 将 YAML 中的占位符项解析为 PlaceholderSpec
// 支持两种格式：
//   - 简单字符串格式: "URLParam"
//   - 复杂映射格式: RawRequest: {method: "POST", path: "/", ...}
func parsePlaceholderSpec(item any) (*PlaceholderSpec, error) {
	switch v := item.(type) {
	case string:
		// 简单格式：直接使用字符串作为占位符名称
		return &PlaceholderSpec{Name: v, Config: nil}, nil
	case map[any]any:
		// 复杂格式：映射中的键是占位符名称，值是配置
		for name, conf := range v {
			nameStr, ok := name.(string)
			if !ok {
				continue
			}
			// 尝试解析占位符配置
			parsedConf, err := placeholder.GetPlaceholderConfig(nameStr, conf)
			if err != nil {
				// 配置解析失败，使用不带配置的占位符
				logger.Debugf("Parse placeholder config for %s error: %v, using without config", nameStr, err)
				return &PlaceholderSpec{Name: nameStr, Config: nil}, nil
			}
			return &PlaceholderSpec{Name: nameStr, Config: parsedConf}, nil
		}
	default:
		logger.Debugf("Unknown placeholder type: %T", item)
	}
	return nil, nil
}

// determineChannel 根据占位符类型确定扫描通道
// 只使用调度系统已有的 Channel 值：web-directory, web-generic, web-path, website, javascript
func determineChannel(placeholders []PlaceholderSpec) string {
	for _, ph := range placeholders {
		switch ph.Name {
		case "URLPath", "NonCrudUrlPath":
			return "web-directory"
		}
	}
	return "web-generic"
}

// LoadSingleTemplate 加载单个 YAML 模板文件
func LoadSingleTemplate(templateFile string, c *Config) ([]*YamlFinger, error) {
	if c == nil {
		return nil, nil
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

	// 默认攻击类型
	if tmpl.Type == "" {
		tmpl.Type = "unknown"
	}

	// 解析占位符规范
	placeholderSpecs := []PlaceholderSpec{}
	for _, phItem := range tmpl.Placeholders {
		spec, err := parsePlaceholderSpec(phItem)
		if err != nil {
			logger.Debugf("Parse placeholder error: %v", err)
			continue
		}
		if spec != nil {
			placeholderSpecs = append(placeholderSpecs, *spec)
		}
	}

	if len(placeholderSpecs) == 0 {
		logger.Debugf("No valid placeholders in template: %s", templateFile)
		return nil, nil
	}

	// 根据占位符类型确定扫描通道
	channel := determineChannel(placeholderSpecs)

	yamlScripts := []*YamlFinger{}
	for _, payload := range tmpl.Payloads {
		ys := YamlFinger{
			YamlScript: &YamlScript{
				Payload:      payload,
				Encoder:      tmpl.Encoders,
				Placeholders: placeholderSpecs,
				Type:         tmpl.Type,
				Channel:      channel,
			},
			cfg: c,
		}
		yamlScripts = append(yamlScripts, &ys)
	}
	return yamlScripts, nil
}
