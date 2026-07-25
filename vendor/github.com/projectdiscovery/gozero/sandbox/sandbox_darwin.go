//go:build darwin

package sandbox

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/projectdiscovery/gozero/cmdexec"
	"github.com/projectdiscovery/gozero/types"
)

type Configuration struct {
	Rules []Rule
}

type Action string

const (
	Allow Action = "allow"
	Deny  Action = "deny"
)

type Scope string

const (
	Network   Scope = "network"
	FileWrite Scope = "file-write"
	FileRead  Scope = "file-read"
	Process   Scope = "process"
	Default   Scope = "default"
)

type ArgsType string

const (
	LocalIP  = `local ip "%s"`
	RemoteIP = `local ip "%s"`
	SubPath  = `subpath "%s"`
)

type Rule struct {
	Action Action
	Scope  Scope
	Args   []Arg
}

type Arg struct {
	Type   ArgsType
	Params []any
}

// Sandbox native on windows
type SandboxDarwin struct {
	Config   *Configuration
	confFile string
}

// New sandbox with the given configuration
func New(ctx context.Context, config *Configuration) (Sandbox, error) {
	if ok, err := isSandboxExecInstalled(context.Background()); err != nil || !ok {
		return nil, errors.New("sandbox feature not installed")
	}

	sharedFolder, err := os.MkdirTemp("", "")
	if err != nil {
		return nil, err
	}

	sharedFolder = filepath.Join(sharedFolder, "gozero")

	if err := os.MkdirAll(sharedFolder, 0755); err != nil {
		return nil, err
	}

	confFile := filepath.Join(sharedFolder, "config.sb")
	var confData bytes.Buffer
	confData.WriteString("(version 1)\n")
	confData.WriteString("(allow default)\n")
	for _, rule := range config.Rules {
		if rule.Action != "" {
			confData.WriteString("(" + string(rule.Action) + " ")
		}
		if rule.Scope != "" {
			confData.WriteString(string(rule.Scope) + "* ")
		}
		for _, arg := range rule.Args {
			confData.WriteString(fmt.Sprintf("("+string(arg.Type)+")", arg.Params...))
		}
		if rule.Action != "" {
			confData.WriteString(")")
		}
	}
	if err := os.WriteFile(confFile, confData.Bytes(), 0600); err != nil {
		return nil, err
	}

	log.Println(confData.String())

	s := &SandboxDarwin{Config: config, confFile: confFile}
	return s, nil
}

func (s *SandboxDarwin) Run(ctx context.Context, cmd string) (*types.Result, error) {
	params := []string{"-f", s.confFile}
	params = append(params, strings.Split(cmd, " ")...)
	cmdContext, err := cmdexec.NewCommand("sandbox-exec", params...)
	if err != nil {
		return nil, err
	}
	return cmdContext.Execute(ctx)
}

// RunScript executes a script or source code in the sandbox
func (s *SandboxDarwin) RunScript(ctx context.Context, source string) (*types.Result, error) {
	return nil, ErrNotImplemented
}

// RunSource writes source code to a temporary file, executes it with proper permissions, and cleans up
func (s *SandboxDarwin) RunSource(ctx context.Context, source, interpreter string) (*types.Result, error) {
	return nil, ErrNotImplemented
}

// Start the instance
func (s *SandboxDarwin) Start() error {
	return ErrNotImplemented
}

// Wait for the instance
func (s *SandboxDarwin) Wait() error {
	return ErrNotImplemented
}

// Stop the instance
func (s *SandboxDarwin) Stop() error {
	return ErrNotImplemented
}

// Clear the instance after stop
func (s *SandboxDarwin) Clear() error {
	return os.RemoveAll(s.confFile)
}

func isSandboxExecInstalled(ctx context.Context) (bool, error) {
	cmd := exec.CommandContext(ctx, "sandbox-exec", "-p", "echo", "true")
	err := cmd.Run()
	if err != nil {
		return false, err
	}
	return true, nil
}
