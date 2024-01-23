package types

import (
	"bytes"
	"os/exec"
)

// Note:
// Current use-case does not return a >1mb output from the command
// so we use bytes.Buffer instead of os.File (temporary file)
// with use case changes we can change this to os.File later

// Result contains the result of a command execution.
type Result struct {
	Command string // Include final command that was executed
	Stdout  bytes.Buffer
	Stderr  bytes.Buffer
	exitErr *exec.ExitError // return exit error this includes exit code , command sysusage and more
}

// GetExitError returns the exit error if any.
func (r *Result) GetExitError() *exec.ExitError {
	return r.exitErr
}

// SetExitError sets the exit error (internal use only).
func (r *Result) SetExitError(err *exec.ExitError) {
	r.exitErr = err
}

// GetExitCode returns the exit code of the command.
func (r *Result) GetExitCode() int {
	if r.exitErr == nil {
		return 0
	}
	return r.exitErr.ExitCode()
}
