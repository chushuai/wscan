/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package sqli_detector

import (
	_ "embed"
	"gopkg.in/yaml.v2"
	"regexp"
	"wscan/core/utils/log"
)

type ErrorRegex struct {
	ID    string
	Dbms  string
	Regex *regexp.Regexp
}

func (er *ErrorRegex) Match(data []byte) bool {
	return er.Regex.Match(data)
}

func newErrorRegex(erc *ErrorRegexConfig) *ErrorRegex {
	if reg, err := regexp.Compile(erc.Regex); err == nil {
		return &ErrorRegex{Regex: reg, Dbms: erc.Dbms}
	} else {
		log.Error(err)
	}
	return nil
}

type ErrorRegexConfig struct {
	Regex string `yaml:"regex"`
	Dbms  string `yaml:"dbms"`
}

//go:embed "db_errors.yaml"
var errorsYaml []byte

func NewErrorRegexList() (errorRegexList []*ErrorRegex) {
	errorRegexConfigList := []ErrorRegexConfig{}
	err := yaml.Unmarshal(errorsYaml, &errorRegexConfigList)
	if err != nil {
		log.Fatalf("Failed to parse YAML file: %v", err)
	}
	for _, errorRegexConfig := range errorRegexConfigList {
		if er := newErrorRegex(&errorRegexConfig); er != nil {
			errorRegexList = append(errorRegexList, er)
		}
	}
	return
}

var ErrorRegexList = NewErrorRegexList()
