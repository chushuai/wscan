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
	for _, include := range []string{"/home/cy/cert_work_python/wscan/core/plugins/fingerprint/technologies/nuclei/*"} {
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

				subFps := make(map[string]*FingerprintRule)
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
						//fmt.Println("[+][+]Condition", matcher.Condition)
						//fmt.Println("[+][+]Type", matcher.Type)
						//fmt.Println("[+][+]Words", matcher.Words)
						//fmt.Println("[+][+]Regex", matcher.Regex)
						//fmt.Println("[+][+]DSL", matcher.DSL)
						//fmt.Println("[+][+]Part", matcher.Part)
						//fmt.Println("[+][+]Status", matcher.Status)
						// response.title.bcontains(b"Example Domain")
						if matcher.Condition == "" || matcher.Condition == "or" {
							matcher.Condition = "||"
						} else if matcher.Condition == "and" {
							matcher.Condition = "&&"
						}
						matcherConditions := []string{}
						if matcher.Type.MatcherType == matchers.WordsMatcher {
							for _, word := range matcher.Words {
								word = strings.ReplaceAll(word, "\"", "\\\"")
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
								regex = strings.ReplaceAll(regex, "\\", "\\\\")
								if matcher.Part == "server" {
									matcherConditions = append(matcherConditions, fmt.Sprintf("server"))
								} else if matcher.Part == "header" {
									matcherConditions = append(matcherConditions, fmt.Sprintf("\"%s\".bmatches(response.raw_header)", regex))
								} else {
									matcherConditions = append(matcherConditions, fmt.Sprintf("\"%s\".bmatches(response.body)", regex))
								}
							}
						} else if matcher.Type.MatcherType == matchers.StatusMatcher {
							for _, status := range matcher.Status {
								matcherConditions = append(matcherConditions, fmt.Sprintf("response.status == %d", status))
							}
						} else if matcher.Type.MatcherType == matchers.DSLMatcher {
							for _, dsl := range matcher.DSL {
								matcherConditions = append(matcherConditions, dsl)
							}
						}
						if len(matcherConditions) > 0 {
							//fmt.Println("[+][+]", strings.Join(matcherConditions, fmt.Sprintf(" %s ", matcher.Condition)))
							newMatcherCondition := strings.Join(matcherConditions, fmt.Sprintf(" %s ", matcher.Condition))

							if len(matcherConditions) > 1 {
								newMatcherCondition = fmt.Sprintf("( %s )", newMatcherCondition)
							}
							matchersConditionExpressions = append(matchersConditionExpressions, newMatcherCondition)

							if matcher.Name != "" {
								if _, exists := subFps[matcher.Name]; !exists {
									subFps[matcher.Name] = &FingerprintRule{
										Engine: "fingerprint",
										Info: FingerprintInfo{
											Name:   template.Info.Name,
											Author: template.Info.Authors.String(),
										},
									}
								}
								subFps[matcher.Name].Pscan.Path = fpr.Pscan.Path
								subFps[matcher.Name].Pscan.Expressions = append(subFps[matcher.Name].Pscan.Expressions, newMatcherCondition)
								fmt.Println(matcher.Name, newPath)
							}
						}
					}
					if requestHTTP.MatchersCondition == "and" {

						fpr.Pscan.Expressions = append(fpr.Pscan.Expressions, strings.Join(matchersConditionExpressions, " && "))
					} else {
						fpr.Pscan.Expressions = matchersConditionExpressions
					}

					data, _ := yaml.Marshal(fpr)
					os.WriteFile(newPath, data, 0666)

					for name, subFrp := range subFps {
						subPath := filepath.Join(strings.ReplaceAll(newPath, ".yaml", ""), strings.ReplaceAll(name, "-", "_")) + ".yaml"
						if err := os.MkdirAll(filepath.Dir(subPath), 777); err != nil {
							logger.Fatal(err)
						}
						fmt.Println("subPath", subPath)
						subFrp.Info.Name = fmt.Sprintf("%s (%s)", name, subFrp.Info.Name)
						data, _ := yaml.Marshal(subFrp)
						os.WriteFile(subPath, data, 0666)
					}
					if len(matchersConditionExpressions) > 0 {

					}
				}
				fmt.Print("\n\n")
			} else {
				fmt.Println("[*]", template.Info.Name)
			}

		}
	}
}
