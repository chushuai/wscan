/**
2 * @Author: shaochuyu
3 * @Date: 12/9/23
4 */

package payload

import (
	"fmt"
	"github.com/pkg/errors"
	"testing"
	"wscan/core/plugins/custom_tmpl/payload/encoder"
	"wscan/core/plugins/custom_tmpl/payload/placeholder"
)

func TestSendPayload(t *testing.T) {
	encodedPayload, err := encoder.Apply("URL", "a=10")
	if err != nil {
		t.Error(errors.Wrap(err, "encoding payload"))
	}

	req, err := placeholder.Apply("http://testphp.vulnweb.com/listproducts.php?cat=1", encodedPayload, "URLParam", nil)
	if err != nil {
		t.Error(errors.Wrap(err, "apply placeholder"))
	}
	fmt.Println(req.URL.String())
}
