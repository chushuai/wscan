//go:build linux

package sandbox

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/projectdiscovery/gozero/types"
	"github.com/projectdiscovery/utils/errkit"
)

// BubblewrapConfiguration holds the general configuration for bubblewrap sandboxing
type BubblewrapConfiguration struct {
	// Base directory for temporary sandbox files
	TempDir string

	// Static namespace options (applied to all commands)
	UnsharePID     bool // Create a new PID namespace
	UnshareIPC     bool // Create a new IPC namespace
	UnshareNetwork bool // Create a new network namespace
	UnshareUTS     bool // Create a new UTS namespace
	UnshareUser    bool // Create a new user namespace
	UnshareCgroup  bool // Create a new cgroup namespace

	// Static security options (applied to all commands)
	NewSession bool // Create a new session (prevents TIOCSTI attacks)
	UID        int  // UID to run as inside the sandbox
	GID        int  // GID to run as inside the sandbox

	// Seccomp filter file
	SeccompFile string

	// Static bind mounts (read-only system directories)
	ReadOnlySystemBinds []BindMount

	// Static environment variables
	Environment map[string]string

	// Enable host filesystem access (read-only)
	HostFilesystem bool
}

// BubblewrapCommandOptions holds per-command configuration
type BubblewrapCommandOptions struct {
	// The command to execute
	Command string

	// Arguments for the command
	Args []string

	// Per-command bind mounts (e.g., source file location -> sandbox location)
	CommandBinds []BindMount

	// Working directory for this command
	WorkingDir string

	// Change to this directory before running
	Chdir string

	// Per-command environment variables (merged with static ones)
	Environment map[string]string

	// Input for stdin
	Stdin string
}

// BindMount represents a bind mount configuration
type BindMount struct {
	HostPath    string
	SandboxPath string
}

// Symlink represents a symlink to create in the sandbox
type Symlink struct {
	Target string
	Link   string
}

// BubblewrapSandbox implements sandboxing using bubblewrap (bwrap)
type BubblewrapSandbox struct {
	config *BubblewrapConfiguration
}

// NewBubblewrapSandbox creates a new bubblewrap sandbox
func NewBubblewrapSandbox(ctx context.Context, config *BubblewrapConfiguration) (*BubblewrapSandbox, error) {
	if config == nil {
		return nil, errors.New("config cannot be nil")
	}

	// Check if bwrap is installed
	installed, err := isBubblewrapInstalled(ctx)
	if err != nil || !installed {
		return nil, errors.New("bubblewrap (bwrap) is not installed")
	}

	// Set default temp directory if not provided
	if config.TempDir == "" {
		config.TempDir = filepath.Join(os.TempDir(), "gozero-bubblewrap")
	}

	// Validate configuration
	if err := validateBubblewrapConfig(config); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return &BubblewrapSandbox{
		config: config,
	}, nil
}

// validateBubblewrapConfig validates the bubblewrap configuration
func validateBubblewrapConfig(config *BubblewrapConfiguration) error {
	// Create temp directory if it doesn't exist
	if err := os.MkdirAll(config.TempDir, 0755); err != nil {
		return fmt.Errorf("failed to create temp directory: %w", err)
	}

	return nil
}

// isBubblewrapInstalled checks if bubblewrap (bwrap) is installed and available
func isBubblewrapInstalled(ctx context.Context) (bool, error) {
	cmd := exec.CommandContext(ctx, "bwrap", "--help")
	err := cmd.Run()
	if err != nil {
		return false, err
	}
	return true, nil
}

// Run executes a command in the bubblewrap sandbox with default options
func (b *BubblewrapSandbox) Run(ctx context.Context, cmd string) (*types.Result, error) {
	// Split command into executable and args
	parts := strings.Fields(cmd)
	if len(parts) == 0 {
		return nil, errors.New("empty command")
	}

	executable := parts[0]
	args := parts[1:]

	options := &BubblewrapCommandOptions{
		Command: executable,
		Args:    args,
	}

	return b.ExecuteWithOptions(ctx, options)
}

// RunScript runs a script in the bubblewrap sandbox
func (b *BubblewrapSandbox) RunScript(ctx context.Context, source string) (*types.Result, error) {
	return b.RunSource(ctx, source)
}

// RunSource executes source code in the bubblewrap sandbox
// It creates a specific source directory, places the script file inside, and mounts only that directory
func (b *BubblewrapSandbox) RunSource(ctx context.Context, source string) (*types.Result, error) {
	// Create a specific directory for this source execution
	sourceDir, err := os.MkdirTemp(b.config.TempDir, "source_*")
	if err != nil {
		return nil, fmt.Errorf("failed to create source directory: %w", err)
	}
	defer func() {
		_ = os.RemoveAll(sourceDir)
	}()

	// Create the script file in the source directory
	scriptPath := filepath.Join(sourceDir, "script.sh")
	if err := os.WriteFile(scriptPath, []byte(source), 0755); err != nil {
		return nil, fmt.Errorf("failed to write script to file: %w", err)
	}

	// Create options with bind mount for the source directory
	options := &BubblewrapCommandOptions{
		Command: "bash",
		Args:    []string{"/src/script.sh"},
		CommandBinds: []BindMount{
			{
				HostPath:    sourceDir,
				SandboxPath: "/src",
			},
		},
		WorkingDir: "/src",
	}

	return b.ExecuteWithOptions(ctx, options)
}

// ExecuteWithOptions executes a command with specific per-command options
func (b *BubblewrapSandbox) ExecuteWithOptions(ctx context.Context, options *BubblewrapCommandOptions) (*types.Result, error) {
	if options == nil {
		return nil, errors.New("options cannot be nil")
	}

	if options.Command == "" {
		return nil, errors.New("command cannot be empty")
	}

	// Create a unique sandbox directory for this command execution
	sandboxDir, err := os.MkdirTemp(b.config.TempDir, "sandbox_*")
	if err != nil {
		return nil, fmt.Errorf("failed to create sandbox directory: %w", err)
	}
	defer func() {
		_ = os.RemoveAll(sandboxDir)
	}()

	return b.executeInSandbox(ctx, sandboxDir, options)
}

// executeInSandbox executes a command in the bubblewrap sandbox
func (b *BubblewrapSandbox) executeInSandbox(ctx context.Context, sandboxDir string, options *BubblewrapCommandOptions) (*types.Result, error) {
	// Build the bwrap command with both static and per-command options
	bwrapArgs := b.buildBubblewrapArgs(sandboxDir, options)

	// Add the command to execute
	bwrapArgs = append(bwrapArgs, options.Command)
	bwrapArgs = append(bwrapArgs, options.Args...)

	// Execute the command
	cmd := exec.CommandContext(ctx, "bwrap", bwrapArgs...)

	// Create result
	result := &types.Result{
		Command: fmt.Sprintf("bwrap %s", strings.Join(bwrapArgs, " ")),
	}

	// Set stdin if provided
	if options.Stdin != "" {
		cmd.Stdin = strings.NewReader(options.Stdin)
	}

	// Capture output
	cmd.Stdout = &result.Stdout
	cmd.Stderr = &result.Stderr

	// Run the command
	if err := cmd.Start(); err != nil {
		return result, errkit.New("failed to start bubblewrap command: %w", err)
	}

	if err := cmd.Wait(); err != nil {
		if execErr, ok := err.(*exec.ExitError); ok {
			result.SetExitError(execErr)
		}
		return result, errkit.New("bubblewrap command failed: %w", err)
	}

	return result, nil
}

// buildBubblewrapArgs constructs the bwrap command arguments
func (b *BubblewrapSandbox) buildBubblewrapArgs(sandboxDir string, options *BubblewrapCommandOptions) []string {
	args := []string{}

	// Create a temporary root filesystem
	args = append(args, "--unshare-all")
	args = append(args, "--die-with-parent")

	// Add proc and dev
	args = append(args, "--proc", "/proc")
	args = append(args, "--dev", "/dev")

	// Add tmpfs for /tmp and /run
	args = append(args, "--tmpfs", "/tmp")
	args = append(args, "--tmpfs", "/run")

	// Add the sandbox directory (unique per execution) as root
	args = append(args, "--bind", sandboxDir, "/")

	// Add namespace options
	if b.config.UnsharePID {
		args = append(args, "--unshare-pid")
	}
	if b.config.UnshareIPC {
		args = append(args, "--unshare-ipc")
	}
	if b.config.UnshareNetwork {
		args = append(args, "--unshare-net")
	}
	if b.config.UnshareUTS {
		args = append(args, "--unshare-uts")
	}
	if b.config.UnshareUser {
		args = append(args, "--unshare-user")
	}

	// Add session protection
	if b.config.NewSession {
		args = append(args, "--new-session")
	}

	// Add UID/GID mapping
	if b.config.UnshareUser {
		if b.config.UID > 0 {
			args = append(args, "--uid", fmt.Sprintf("%d", b.config.UID))
		}
		if b.config.GID > 0 {
			args = append(args, "--gid", fmt.Sprintf("%d", b.config.GID))
		}
	}

	// Add host filesystem access if enabled
	if b.config.HostFilesystem {
		// Bind mount essential directories as read-only
		args = append(args, "--ro-bind", "/usr", "/usr")
		args = append(args, "--ro-bind", "/lib", "/lib")
		args = append(args, "--ro-bind", "/lib64", "/lib64")
		args = append(args, "--ro-bind", "/bin", "/bin")
		args = append(args, "--ro-bind", "/sbin", "/sbin")
	}

	// Add static read-only system binds
	for _, bind := range b.config.ReadOnlySystemBinds {
		hostPath, err := filepath.Abs(bind.HostPath)
		if err != nil {
			continue
		}
		args = append(args, "--ro-bind", hostPath, bind.SandboxPath)
	}

	// Add static environment variables
	for key, value := range b.config.Environment {
		args = append(args, "--setenv", key, value)
	}

	// Add per-command bind mounts (e.g., source directories)
	for _, bind := range options.CommandBinds {
		hostPath, err := filepath.Abs(bind.HostPath)
		if err != nil {
			continue
		}
		args = append(args, "--bind", hostPath, bind.SandboxPath)
	}

	// Add per-command environment variables (merged with static ones)
	for key, value := range options.Environment {
		args = append(args, "--setenv", key, value)
	}

	// Add chdir if specified
	if options.Chdir != "" {
		args = append(args, "--chdir", options.Chdir)
	}

	return args
}

// Start starts the sandbox (no-op for bubblewrap as it runs per-command)
func (b *BubblewrapSandbox) Start() error {
	return nil
}

// Wait waits for the sandbox to finish (no-op for bubblewrap)
func (b *BubblewrapSandbox) Wait() error {
	return nil
}

// Stop stops the sandbox (no-op for bubblewrap as each command runs independently)
func (b *BubblewrapSandbox) Stop() error {
	return nil
}

// Clear cleans up the temp directory
func (b *BubblewrapSandbox) Clear() error {
	if b.config.TempDir != "" {
		return os.RemoveAll(b.config.TempDir)
	}
	return nil
}
