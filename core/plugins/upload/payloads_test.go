/**
2 * @Author: shaochuyu
3 * @Date: 1/15/24
4 */

package upload

import (
	"fmt"
	"testing"
)

func TestPayload(t *testing.T) {
	fmt.Println("\xff\xd8<?php echo md5('Bgr7nwz9'); ?>\xff\xd9")
}

func TestGenerateWebshells(t *testing.T) {
	for _, v := range GenerateWebshells() {
		fmt.Printf("%s\n%s", v.NamesForUpload, string(v.Content))
	}

}
