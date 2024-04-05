/**
2 * @Author: shaochuyu
3 * @Date: 4/4/24
4 */

package fingerprint

import (
	"fmt"
	"github.com/projectdiscovery/nuclei/v3/pkg/operators/matchers"
	"github.com/projectdiscovery/nuclei/v3/pkg/templates"
	"gopkg.in/yaml.v3"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"wscan/core/utils"
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

func TestFp(t *testing.T) {
	pocPaths := []string{}
	for _, include := range []string{"/home/cy/cert_work_python/wscan/core/plugins/fingerprint/technologies/nuclei/technologies/*"} {
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
	for _, ppocPath := range pocPaths {
		if template, err := LoadNucleiYamlPOC(ppocPath); err == nil {
			if template.RequestsHTTP != nil {
				fmt.Println("#", len(template.RequestsHTTP), ppocPath)
				newPath := strings.ReplaceAll(ppocPath, "ingerprint/technologies/nuclei", "ingerprint/technologies/wscan")
				fmt.Println(filepath.Dir(newPath))
				fmt.Println(filepath.Base(newPath))
				if err := os.MkdirAll(filepath.Dir(newPath), 777); err != nil {
					logger.Fatal(err)
				}
				fmt.Println(template.Info.Name)
				for i, requestHTTP := range template.RequestsHTTP {
					fpr := FingerprintRule{
						Engine: "fingerprint",
						Info: FingerprintInfo{
							Name:   template.Info.Name,
							Author: template.Info.Authors.String(),
						},
					}
					for _, path := range requestHTTP.Path {
						if path == "{{BaseURL}}" {
							path = "/"
						} else {
							path = strings.ReplaceAll(path, "{{BaseURL}}", "")
						}
						fpr.Pscan.Path = append(fpr.Pscan.Path, path)
					}
					fmt.Println("####", i)
					fmt.Println("[+]", requestHTTP.Path)
					fmt.Println("[+]MatchersCondition", requestHTTP.MatchersCondition)
					matchersConditionExpressions := []string{}
					for _, matcher := range requestHTTP.Matchers {
						fmt.Println("[+++++]")
						fmt.Println("[+][+]Name", matcher.Name)
						fmt.Println("[+][+]Condition", matcher.Condition)
						fmt.Println("[+][+]Type", matcher.Type)
						fmt.Println("[+][+]Words", matcher.Words)
						fmt.Println("[+][+]Regex", matcher.Regex)
						fmt.Println("[+][+]DSL", matcher.DSL)
						fmt.Println("[+][+]Part", matcher.Part)
						fmt.Println("[+][+]Status", matcher.Status)

						// response.status == 200 && response.content_type.contains("json") && response.body.bcontains(b"success") && response.body.bcontains(bytes(r2))
						// "root:[x*]:0:0:".bmatches(response.body)
						// response.title.bcontains(b"Example Domain")
						if matcher.Condition == "" {
							matcher.Condition = "or"
						}
						matcherConditions := []string{}
						if matcher.Type.MatcherType == matchers.WordsMatcher {
							for _, word := range matcher.Words {
								if matcher.Part == "server" {
									matcherConditions = append(matcherConditions, fmt.Sprintf("response.headers[\"server\"].contains(\"%s\")", word))
								} else if matcher.Part == "header" {
									matcherConditions = append(matcherConditions, fmt.Sprintf("response.raw_header.bcontains(b\"%s\")", word))
								} else {
									matcherConditions = append(matcherConditions, fmt.Sprintf("response.body.bcontains(b\"%s\")", word))
								}
							}

						} else if matcher.Type.MatcherType == matchers.RegexMatcher {
							for _, regex := range matcher.Regex {
								if matcher.Part == "server" {
									matcherConditions = append(matcherConditions, fmt.Sprintf("server"))
								} else if matcher.Part == "header" {
									matcherConditions = append(matcherConditions, fmt.Sprintf("\"%s\".bmatches(response.raw_header)", regex))
								} else if matcher.Part == "body" {
									matcherConditions = append(matcherConditions, fmt.Sprintf("\"%s\".bmatches(response.body)", regex))
								}
							}
						} else if matcher.Type.MatcherType == matchers.StatusMatcher {
							for _, status := range matcher.Status {
								matcherConditions = append(matcherConditions, fmt.Sprintf("response.status == %d", status))
							}
						}
						if len(matcherConditions) > 0 {
							fmt.Println("[+][+]", strings.Join(matcherConditions, fmt.Sprintf(" %s ", matcher.Condition)))

							matchersConditionExpressions = append(matchersConditionExpressions, strings.Join(matcherConditions, fmt.Sprintf(" %s ", matcher.Condition)))
						}
					}
					if requestHTTP.MatchersCondition == "and" {
						fpr.Pscan.Expressions = append(fpr.Pscan.Expressions, strings.Join(matchersConditionExpressions, " and "))
					} else {
						fpr.Pscan.Expressions = matchersConditionExpressions
					}

					data, _ := yaml.Marshal(fpr)

					os.WriteFile(newPath, data, 0666)
				}
				fmt.Print("\n\n")
			} else {
				fmt.Println("[*]", template.Info.Name)
			}

		}
	}

}
