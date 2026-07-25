package sandbox

import "errors"

var (
	ErrNotImplemented = errors.New("not implemented")
	ErrAgentRequired  = errors.New("requires agent installed on the sandbox")
)
