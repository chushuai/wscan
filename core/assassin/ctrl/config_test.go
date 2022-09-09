/**
2 * @Author: shaochuyu
3 * @Date: 9/10/22
4 */

package ctrl

import (
	"fmt"
	"gopkg.in/yaml.v3"
	"testing"
)

func TestNewExampleConfig(t *testing.T) {
	config := NewDefaultConfig()
	d, err := yaml.Marshal(&config)
	if err != nil {
		t.Fatalf("error: %v", err)
		return
	}
	fmt.Printf("dump:\n%s\n\n", string(d))

}
