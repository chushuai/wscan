package gozero

import (
	"context"
	"fmt"
	"os/exec"

	"github.com/projectdiscovery/gozero/cmdexec"
	"github.com/projectdiscovery/gozero/sandbox"
	"github.com/projectdiscovery/gozero/types"
)

// VirtualEnvType represents the type of virtual environment
type VirtualEnvType uint8

const (
	VirtualEnvLinux VirtualEnvType = iota
	VirtualEnvDarwin
	VirtualEnvWindows
	VirtualEnvDocker
)

// Gozero is executor for gozero
type Gozero struct {
	Options *Options
}

// New creates a new gozero executor
func New(options *Options) (*Gozero, error) {
	if len(options.Engines) == 0 {
		return nil, ErrNoEngines
	}
	// attempt to locate the interpreter by executing it
	for _, engine := range options.Engines {
		// use lookpath to check if engine is available
		// this ignores path confusion issues where binary with same name exists in current path
		fpath, err := exec.LookPath(engine)
		if err != nil {
			continue
		} else {
			options.engine = fpath
			break
		}
	}
	if options.engine == "" {
		return nil, ErrNoValidEngine
	}
	return &Gozero{Options: options}, nil
}

// Eval evaluates the source code and returns the output
// input = stdin , src = source code , args = arguments
func (g *Gozero) Eval(ctx context.Context, src, input *Source, args ...string) (*types.Result, error) {
	if g.Options.EarlyCloseFileDescriptor {
		_ = src.File.Close()
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
	if g.Options.DebugMode {
		gcmd.EnableDebugMode()
	}
	gcmd.SetStdin(input.File) // stdin
	// add both input and src variables if any
	gcmd.AddVars(src.Variables...) // variables as environment variables
	gcmd.AddVars(input.Variables...)
	return gcmd.Execute(ctx)
}

// EvalWithVirtualEnv evaluates the source code in a virtual environment and returns the output
// This function passes the source code into the virtual environment and external parameters as environment variables
func (g *Gozero) EvalWithVirtualEnv(ctx context.Context, envType VirtualEnvType, src, input *Source, dockerConfig *sandbox.DockerConfiguration, args ...string) (*types.Result, error) {
	// Read source code content
	srcContent, err := src.ReadAll()
	if err != nil {
		return nil, err
	}

	// Prepare environment variables from source and input variables
	envVars := make(map[string]string)

	// Add source variables as environment variables
	for _, variable := range src.Variables {
		envVars[variable.Name] = variable.Value
	}

	// Add input variables as environment variables
	for _, variable := range input.Variables {
		envVars[variable.Name] = variable.Value
	}

	// Handle different virtual environment types
	switch envType {
	case VirtualEnvDocker:
		// Update Docker configuration with environment variables
		dockerConfig.Environment = envVars

		// Create Docker sandbox with updated configuration
		dockerSandbox, err := sandbox.NewDockerSandbox(ctx, dockerConfig)
		if err != nil {
			return nil, err
		}

		// Use the engine as the interpreter
		interpreter := g.Options.engine
		if interpreter == "" {
			// Fallback to first engine if engine not set
			if len(g.Options.Engines) > 0 {
				interpreter = g.Options.Engines[0]
			} else {
				interpreter = "sh" // Default to shell
			}
		}

		// Execute the source code in the Docker container
		result, err := dockerSandbox.RunSource(ctx, string(srcContent), interpreter)
		if err != nil {
			return nil, err
		}

		return result, nil

	case VirtualEnvLinux, VirtualEnvDarwin, VirtualEnvWindows:
		// For now, these are not implemented - they would use the regular Eval method
		// In the future, these could be implemented to use different sandboxing mechanisms
		return nil, fmt.Errorf("virtual environment type %d is not yet implemented", envType)

	default:
		return nil, fmt.Errorf("unsupported virtual environment type: %d", envType)
	}
}
