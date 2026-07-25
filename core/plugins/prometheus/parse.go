/**
2 * @Author: shaochuyu
3 * @Date: 6/25/23
4 */

package prometheus

import (
	"io"

	"github.com/pkg/errors"
	"gopkg.in/yaml.v2"
	"os"
	"sync"
	logger "wscan/core/utils/log"
)

var PocPool = sync.Pool{
	New: func() any {
		return new(Poc)
	},
}

func ParsePocFromReader(r io.Reader) (*Poc, error) {
	poc := PocPool.Get().(*Poc)

	err := yaml.NewDecoder(r).Decode(poc)

	if err != nil {
		return nil, err
	}
	if poc.Name == "" {
		return nil, errors.Errorf("Wscan poc name can't be nil")
	}

	if poc.Transport == "" {
		poc.Transport = "http"
	}
	if poc.Detail.Fingerprint == nil {
		poc.Detail.Fingerprint = &Fingerprint{}
	}

	return poc, nil
}

func ParsePoc(filename string) (*Poc, error) {
	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	poc, err := ParsePocFromReader(f)
	if err != nil {
		logger.Errorf("%s , %s", filename, err.Error())
		return nil, err
	}
	return poc, nil
}
