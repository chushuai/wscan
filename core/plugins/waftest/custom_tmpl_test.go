/**
* @Author: shaochuyu
* @Date: 12/9/23
 */
package waftest

import (
	"fmt"
	"testing"
	"wscan/core/plugins/base"
)

func TestTemplate(t *testing.T) {
	c := &Config{
		PluginBaseConfig: base.PluginBaseConfig{Name: "waftest", Enabled: true},
		PassStatusCodes:  []int{200, 404},
		BlockStatusCodes: []int{403},
	}
	if yss, err := LoadSingleTemplate("./tmpl/owasp/ldap-injection.yml", c); err != nil {
		t.Error(err)
	} else {
		for _, ys := range yss {
			fmt.Printf("Type: %s, Channel: %s, Payload: %s, Encoders: %v, Placeholders: %v\n",
				ys.Type, ys.Channel, ys.Payload, ys.Encoder, ys.Placeholders)
		}
	}
}

func TestLoadSingleTemplateWithComplexPlaceholder(t *testing.T) {
	c := &Config{
		PluginBaseConfig: base.PluginBaseConfig{Name: "waftest", Enabled: true},
		PassStatusCodes:  []int{200, 404},
		BlockStatusCodes: []int{403},
	}
	if yss, err := LoadSingleTemplate("./tmpl/community/community-lfi-multipart.yml", c); err != nil {
		t.Error(err)
	} else {
		for _, ys := range yss {
			fmt.Printf("Type: %s, Channel: %s, Placeholders: %v\n",
				ys.Type, ys.Channel, ys.Placeholders)
			// Verify RawRequest placeholder was parsed correctly
			for _, ph := range ys.Placeholders {
				if ph.Name == "RawRequest" && ph.Config != nil {
					fmt.Println("RawRequest config parsed successfully!")
				}
			}
		}
	}
}

func TestLoadSingleTemplateNilConfig(t *testing.T) {
	// nil config should return nil, nil without error
	yss, err := LoadSingleTemplate("./tmpl/owasp/ldap-injection.yml", nil)
	if err != nil {
		t.Errorf("Expected nil error, got: %v", err)
	}
	if yss != nil {
		t.Errorf("Expected nil result, got: %v", yss)
	}
}
