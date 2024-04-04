/**
2 * @Author: shaochuyu
3 * @Date: 4/4/24
4 */

package fingerprint

import (
	"github.com/projectdiscovery/nuclei/v3/pkg/templates"
	"gopkg.in/yaml.v2"
	"io"
	"os"
	"path/filepath"
	logger "wscan/core/utils/log"
)

func LoadNucleiYamlPOC(pocFile string) (*templates.Template, error) {
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
	return template, err
}
