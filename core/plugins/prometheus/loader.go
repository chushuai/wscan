/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package prometheus

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"wscan/core/plugins/base"
	"wscan/core/plugins/prometheus/goby"
	"wscan/core/plugins/prometheus/pocs/gopoc"
	"wscan/core/utils"
	logger "wscan/core/utils/log"

	"github.com/projectdiscovery/nuclei/v3/pkg/templates"
	"gopkg.in/yaml.v2"
)

func LoadAllPOC(c *Config) (allPoc []base.FingerFactory) {
	allPoc = append(allPoc, gopoc.LoadGolangPOC()...)
	return
}

type YamlFormat struct {
	ID        string `yaml:"id"`
	Name      string `yaml:"name"`
	Manual    bool   `yaml:"manual"`
	Transport string `yaml:"transport"`
}

const (
	PocTypeXray int = iota
	PocTypeNuclei
)

func identifyYamlPocType(pocFile string) int {
	pocPath, err := filepath.Abs(pocFile)
	if err != nil {
		logger.Infof("Get poc filepath error: %s", pocFile)
		return -1
	}
	f, err := os.Open(pocPath)
	if err != nil {
		return -1
	}
	defer f.Close()

	data, _ := io.ReadAll(f)
	var yf YamlFormat
	err = yaml.Unmarshal([]byte(data), &yf)
	if err != nil {
		return -1
	}
	if yf.Name != "" && yf.Transport != "" {
		return PocTypeXray
	} else if yf.ID != "" {
		return PocTypeNuclei
	}
	return -1 // 表示未知类型
}

func LoadYamlPOC(c *Config) (ret []base.FingerFactory) {
	pocPaths := []string{}

	includePOCs := []string{}
	if len(c.POC) > 0 {
		includePOCs = c.POC
	} else if len(c.IncludePOC) > 0 {
		includePOCs = c.IncludePOC
	}
	for _, include := range includePOCs {
		if pocFiles, err := filepath.Glob(include); err == nil {
			for _, d := range pocFiles {
				if utils.IsDir(d) {
					if files, err := utils.GetAllFiles(d); err == nil {
						pocPaths = append(pocPaths, files...)
					}
				} else {
					pocPaths = append(pocPaths, d)
				}
			}
		} else {
			logger.Errorf("Path glob match error: " + err.Error())
		}
	}
	for _, pocFile := range pocPaths {
		logger.Debugf("Load from poc path: %v", pocFile)
		// 只解析yml或yaml文件
		if strings.HasSuffix(pocFile, ".yml") || strings.HasSuffix(pocFile, ".yaml") {
			pocType := identifyYamlPocType(pocFile)
			if pocType == PocTypeXray {
				if poc, err := LoadSingleYamlPOC(pocFile); err == nil {
					ret = append(ret, poc)
				}
			} else if pocType == PocTypeNuclei {
				if poc, err := LoadNucleiYamlPOC(pocFile); err == nil {
					ret = append(ret, poc)
				}
			}

		} else if strings.HasSuffix(pocFile, ".json") {
			if poc, err := LoadSingleJsonPOC(pocFile); err == nil {
				ret = append(ret, poc)
			}
		}
	}
	logger.Infof("Load [%d] yaml poc(s),", len(ret))
	return
}

func LoadNucleiYamlPOC(pocFile string) (*NucleiFinger, error) {
	pocPath, err := filepath.Abs(pocFile)
	if err != nil {
		logger.Infof("Get poc filepath error: %s", pocFile)
		return nil, err
	}
	f, err := os.Open(pocPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	data, _ := io.ReadAll(f)
	template := &templates.Template{}
	if err = yaml.Unmarshal(data, template); err != nil {
		return nil, err
	}
	if len(template.Workflows) > 0 {
		return nil, errors.New("nuclei workflows disable")
	}

	template, err = templates.Parse(pocFile, nil, &ExecuterOptions)
	if err != nil {
		logger.Errorf("templates.Parse() err, %v", err)
		return nil, err
	}
	if maxRequest, ok := template.Info.Metadata["max-request"].(int); ok {
		if maxRequest > 10 {
			logger.Infof("%s, max-request %d, 请求数据超过系统阈值10，被禁用。", template.Info.Name, maxRequest)
			return nil, errors.New("请求数据超过系统阈值10，被禁用")
		}
	}
	scanRootOnly := true
	if strings.Contains(string(data), "{{BaseURL}}") {
		scanRootOnly = false
	}
	template.Path = pocPath
	return &NucleiFinger{
		poc:          template,
		pocPath:      pocPath,
		scanRootOnly: scanRootOnly,
	}, nil
}

func LoadSingleYamlPOC(pocFile string) (*YamlFinger, error) {
	if !utils.FileExists(pocFile) {
		logger.Debugf("Poc file not found: '%v'", pocFile)
	}
	pocPath, err := filepath.Abs(pocFile)
	if err != nil {
		logger.Infof("Get poc filepath error: %s", pocFile)
		return nil, err
	}
	logger.Debugf("Load poc file: %v", pocFile)
	xrayPoc, err := ParsePoc(pocPath)
	if err == nil {
		return &YamlFinger{
			pocPath: pocPath,
			YamlScript: &YamlScript{
				Name: xrayPoc.Name,
			},
			poc: xrayPoc,
		}, nil
	} else {
		logger.Debugf("Poc[%s] Parse error", pocFile)
		return nil, err
	}
}

func LoadSingleJsonPOC(pocPath string) (*JsonFinger, error) {
	var poc goby.Poc
	var bytes []byte
	bytes, err := os.ReadFile(pocPath)
	if err != nil {
		logger.Error(err)
		return nil, err
	}
	err = json.Unmarshal(bytes, &poc)
	if err != nil {
		logger.Error(err)
		return nil, err
	}

	return &JsonFinger{
		pocPath: pocPath,
		poc:     &poc,
	}, nil
}
