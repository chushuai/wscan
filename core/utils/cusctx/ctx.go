/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package cusctx

import (
	"context"
	"os"
	"os/signal"
	"syscall"
)

func WithSignal(parent context.Context, sig syscall.Signal) (context.Context, func()) {
	ctx, cancel := context.WithCancel(parent)

	c := make(chan os.Signal, 1)
	signal.Notify(c, sig)

	go func() {
		defer signal.Stop(c)
		select {
		case <-c:
			cancel()
		case <-ctx.Done():
		}
	}()

	return ctx, cancel
}
