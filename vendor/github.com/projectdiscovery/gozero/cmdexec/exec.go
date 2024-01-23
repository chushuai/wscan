// cmdexec package is wrapper around os/exec and handles common use cases while executing commands.
package cmdexec

import (
	"context"
	"io"
	"os/exec"

	"github.com/projectdiscovery/gozero/types"
	errorutil "github.com/projectdiscovery/utils/errors"
)

// Command is a command to execute.
type Command struct {
	Binary string // Full path to the binary to execute
	Args   []string
	Env    []string
	stdin  io.Reader
}

// NewCommand creates a new command with the provided binary and arguments.
func NewCommand(binary string, args ...string) (*Command, error) {
	execpath, err := exec.LookPath(binary)
	if err != nil {
		return nil, err
	}
	return &Command{Binary: execpath, Args: args}, nil
}

// SetEnv sets the environment variables for the command.
func (c *Command) SetEnv(env []string) {
	c.Env = env
}

// AddVars adds variables to the command.
func (c *Command) AddVars(vars ...types.Variable) {
	for _, v := range vars {
		c.Env = append(c.Env, v.String())
	}
}

// SetStdin sets the stdin for the command.
func (c *Command) SetStdin(stdin io.Reader) {
	c.stdin = stdin
}

// Execute executes the command and returns the output.
func (c *Command) Execute(ctx context.Context) (*types.Result, error) {
	cmd := exec.CommandContext(ctx, c.Binary, c.Args...)
	if len(c.Env) > 0 {
		// by default we allow existing environment variables to be inherited
		cmd.Env = append(cmd.Environ(), c.Env...)
	}
	res := &types.Result{Command: cmd.String()}
	cmd.Stdout = &res.Stdout
	cmd.Stderr = &res.Stderr
	if c.stdin != nil {
		cmd.Stdin = c.stdin
	}

	if err := cmd.Start(); err != nil {
		// this error indicates that command did not start at all (e.g. binary not found)
		// or something similar
		return res, errorutil.NewWithErr(err).Msgf("failed to start command got: %v", res.Stderr.String())
	}

	if err := cmd.Wait(); err != nil {
		if execErr, ok := err.(*exec.ExitError); ok {
			res.SetExitError(execErr)
		}
		// this error indicates that command started but exited with non-zero exit code
		return res, errorutil.NewWithErr(err).Msgf("failed to exec command got: %v", res.Stderr.String())
	}
	return res, nil
}

// Extra Notes:
// go before 1.21 did not follow symlinks when executing binaries and python installed from ms store creates a symlink
// this is fixed https://github.com/golang/go/issues/42919 but just in case a workaround is to execute using low level api i.e os.startprocess
