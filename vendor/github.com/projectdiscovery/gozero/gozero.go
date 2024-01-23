package gozero

import (
	"context"
	"errors"
	"os/exec"
	"time"

	"github.com/projectdiscovery/gozero/cmdexec"
	"github.com/projectdiscovery/gozero/types"
	errorutil "github.com/projectdiscovery/utils/errors"
)

// Gozero is executor for gozero
type Gozero struct {
	Options *Options
}

// New creates a new gozero executor
func New(options *Options) (*Gozero, error) {
	// attempt to locate the interpreter by executing it
	for _, engine := range options.Engines {
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		defer cancel()

		cmd := exec.CommandContext(ctx, engine)
		err := cmd.Run()
		if err == nil || errorutil.IsAny(err, exec.ErrWaitDelay) {
			options.engine = engine
			break
		}
	}
	if options.engine == "" {
		return nil, errors.New("no valid engine found")
	}
	return &Gozero{Options: options}, nil
}

// Eval evaluates the source code and returns the output
// input = stdin , src = source code , args = arguments
func (g *Gozero) Eval(ctx context.Context, src, input *Source, args ...string) (*types.Result, error) {
	if g.Options.EarlyCloseFileDescriptor {
		src.File.Close()
	}
	allargs := []string{}
	allargs = append(allargs, g.Options.Args...)
	allargs = append(allargs, src.Filename)
	allargs = append(allargs, args...)
	gcmd, err := cmdexec.NewCommand(g.Options.engine, allargs...)
	if err != nil {
		// returns error if binary(engine) does not exist
		return nil, err
	}
	gcmd.SetStdin(input.File) // stdin
	// add both input and src variables if any
	gcmd.AddVars(src.Variables...) // variables as environment variables
	gcmd.AddVars(input.Variables...)
	return gcmd.Execute(ctx)
}
