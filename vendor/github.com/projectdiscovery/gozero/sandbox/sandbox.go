package sandbox

import (
	"context"

	"github.com/projectdiscovery/gozero/types"
)

type Sandbox interface {
	Run(ctx context.Context, cmd string) (*types.Result, error)
	RunScript(ctx context.Context, source string) (*types.Result, error)
	RunSource(ctx context.Context, source string, interpreter string) (*types.Result, error)
	Start() error
	Wait() error
	Stop() error
	Clear() error
}
