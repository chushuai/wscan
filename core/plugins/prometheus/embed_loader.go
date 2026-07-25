/**
* @Author: shaochuyu
* @Date: 6/14/26
 */
package prometheus

import (
	"embed"
	"errors"
	"io"
	"strings"
	"wscan/core/plugins/base"
	logger "wscan/core/utils/log"

	"github.com/projectdiscovery/nuclei/v3/pkg/templates"
	"gopkg.in/yaml.v2"
)

//go:embed pocs/yamlpoc
var embeddedYamlPocs embed.FS

// LoadEmbeddedYamlPOC loads all YAML POCs from the embedded filesystem.
func LoadEmbeddedYamlPOC() (ret []base.FingerFactory) {
	pocPaths := listEmbeddedYamlPocs("pocs/yamlpoc")
	for _, pocPath := range pocPaths {
		if !strings.HasSuffix(pocPath, ".yml") && !strings.HasSuffix(pocPath, ".yaml") {
			continue
		}
		pocType := identifyEmbeddedYamlPocType(pocPath)
		if pocType == PocTypeXray {
			if poc, err := LoadSingleEmbeddedYamlPOC(pocPath); err == nil {
				ret = append(ret, poc)
			} else {
				logger.Debugf("Embedded xray POC load error [%s]: %v", pocPath, err)
			}
		} else if pocType == PocTypeNuclei {
			if poc, err := LoadEmbeddedNucleiYamlPOC(pocPath); err == nil {
				ret = append(ret, poc)
			} else {
				logger.Debugf("Embedded nuclei POC load error [%s]: %v", pocPath, err)
			}
		}
	}
	logger.Infof("Load [%d] embedded yaml poc(s)", len(ret))
	return
}

// listEmbeddedYamlPocs recursively lists all files in the embedded FS directory.
func listEmbeddedYamlPocs(dir string) []string {
	var paths []string
	entries, err := embeddedYamlPocs.ReadDir(dir)
	if err != nil {
		return paths
	}
	for _, entry := range entries {
		fullPath := dir + "/" + entry.Name()
		if entry.IsDir() {
			paths = append(paths, listEmbeddedYamlPocs(fullPath)...)
		} else {
			paths = append(paths, fullPath)
		}
	}
	return paths
}

// identifyEmbeddedYamlPocType detects whether an embedded POC is xray or nuclei format.
func identifyEmbeddedYamlPocType(pocPath string) int {
	data, err := embeddedYamlPocs.ReadFile(pocPath)
	if err != nil {
		return -1
	}
	var yf YamlFormat
	if err = yaml.Unmarshal(data, &yf); err != nil {
		return -1
	}
	if yf.Name != "" && yf.Transport != "" {
		return PocTypeXray
	} else if yf.ID != "" {
		return PocTypeNuclei
	}
	return -1
}

// LoadSingleEmbeddedYamlPOC loads an xray-format POC from the embedded filesystem.
func LoadSingleEmbeddedYamlPOC(pocPath string) (*YamlFinger, error) {
	f, err := embeddedYamlPocs.Open(pocPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	xrayPoc, err := ParsePocFromReader(f)
	if err != nil {
		return nil, err
	}
	return &YamlFinger{
		pocPath:    pocPath,
		YamlScript: &YamlScript{Name: xrayPoc.Name},
		poc:        xrayPoc,
	}, nil
}

// LoadEmbeddedNucleiYamlPOC loads a nuclei-format POC from the embedded filesystem.
func LoadEmbeddedNucleiYamlPOC(pocPath string) (*NucleiFinger, error) {
	f, err := embeddedYamlPocs.Open(pocPath)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	data, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}

	template := &templates.Template{}
	if err = yaml.Unmarshal(data, template); err != nil {
		return nil, err
	}
	if len(template.Workflows) > 0 {
		return nil, errors.New("nuclei workflows disable")
	}

	opts := ExecuterOptions.Copy()
	opts.TemplatePath = pocPath

	reader := strings.NewReader(string(data))
	template, err = templates.ParseTemplateFromReader(reader, nil, opts)
	if err != nil {
		logger.Errorf("ParseTemplateFromReader() err for %s, %v", pocPath, err)
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
