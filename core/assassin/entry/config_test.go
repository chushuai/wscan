/**
2 * @Author: shaochuyu
3 * @Date: 9/10/22
4 */

package entry

import (
	"fmt"
	"gopkg.in/yaml.v3"
	"testing"
)

func TestConfig(t *testing.T) {
	config := NewExampleConfig()
	d, err := yaml.Marshal(config)
	if err != nil {
		t.Fatalf("error: %v", err)
		return
	}
	fmt.Printf("dump:\n%s\n\n", string(d))

}
