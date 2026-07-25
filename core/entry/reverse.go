/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package entry

import (
	"sync"
	"wscan/core/reverse"
	"wscan/core/utils/log"

	"github.com/urfave/cli/v2"
)

func ReverseAction(c *cli.Context) error {
	cfg, err := LoadOrGenConfig(c)
	if err != nil {
		log.Fatal(err)
	}

	wg := sync.WaitGroup{}
	wg.Add(1)
	r := reverse.NewReverse(cfg.Config.Reverse)
	if r == nil {
		log.Fatal("you must set reverse config")
	}
	wg.Wait()
	return nil
}
