/**
2 * @Author: shaochuyu
3 * @Date: 8/4/24
4 */

package js

import (
	"context"
	_ "embed"
	"fmt"
	"gopkg.in/yaml.v2"
	"os"
	"regexp"
	"strings"
	"time"
	"wscan/core/http"
	"wscan/core/model"
	"wscan/core/plugins/base"
	logger "wscan/core/utils/log"
)

//go:embed "sensitive_content_check.yml"
var ruleYaml []byte

// Rule defines the structure of a single regex rule
type Rule struct {
	Title    string         `yaml:"title"`
	Pattern  string         `yaml:"regex"`
	Compiled *regexp.Regexp `yaml:"-"`
}

// RuleSet holds a slice of rules
type RuleSet struct {
	Rules []Rule `yaml:"rules"`
}

func LoadRulesFromFile(filename string) ([]Rule, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	return LoadRulesWithRaw(data)
}

func LoadRulesWithRaw(raw []byte) ([]Rule, error) {
	var ruleSet RuleSet
	err := yaml.Unmarshal(raw, &ruleSet)
	if err != nil {
		return nil, err
	}

	// Compile regexes
	for i := range ruleSet.Rules {
		re, err := regexp.Compile(ruleSet.Rules[i].Pattern)
		if err != nil {
			return nil, err
		}
		ruleSet.Rules[i].Compiled = re // Store compiled regex
	}

	return ruleSet.Rules, nil
}

// ScanText checks for sensitive information in the given text
func ScanText(text string, rules []Rule) {
	for _, rule := range rules {
		if rule.Compiled == nil {
			logger.Printf("No compiled regex for rule %s", rule.Title)
			continue
		}

		matches := rule.Compiled.FindAllString(text, -1)
		if matches != nil {
			for _, match := range matches {
				// Check if the match should be ignored based on the content
				ignored := []string{"function", "encodeURIComponent", "XMLHttpRequest"}
				shouldIgnore := false
				for _, ignore := range ignored {
					if strings.Contains(match, ignore) {
						shouldIgnore = true
						break
					}
				}
				if shouldIgnore {
					continue
				}
				fmt.Printf("Found sensitive information:\nType: %s\nMatch: %s\n", rule.Title, match)
			}
		}
	}
}

type SensitiveContentCheck struct {
	rules []Rule
}

func (p *SensitiveContentCheck) Finger() *base.Finger {
	return &base.Finger{
		CheckAction: func(ctx context.Context, ab *base.Apollo) error {
			flow := ab.GetTargetFlow()
			logger.Infof("Start js/sensitive-content-check, %s", flow.Request.URL())
			for _, rule := range p.rules {
				if rule.Compiled == nil {
					logger.Printf("No compiled regex for rule %s", rule.Title)
					continue
				}
				matches := rule.Compiled.FindAllString(flow.Response.Text, -1)
				if matches != nil {
					fp := &model.Vuln{
						Payload: rule.Pattern,
						Param:   nil,
						Flow:    []*http.Flow{{Request: flow.Request, Response: flow.Response}},
						Binding: &model.VulnBinding{Plugin: "js/sensitive-content-check", Category: "js/sensitive-content-check", ID: "js/sensitive-content-check"},
						Extra: map[string]interface{}{
							"title":   rule.Title,
							"matches": matches,
						},
						CreateTime: time.Now().Unix(),
					}
					fp.SetTargetURL(flow.Request.URL())
					ab.OutputVuln(fp)

				}
			}
			return nil
		},
		Channel: "javascript",
		Binding: &model.VulnBinding{ID: "js/sensitive-content-check", Plugin: "js/sensitive-content-check", Category: "js/sensitive-content-check"},
	}
}
