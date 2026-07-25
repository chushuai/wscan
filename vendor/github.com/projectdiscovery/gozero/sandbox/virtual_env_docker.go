package sandbox

import (
	"context"
	"fmt"
	"log"
	"os/exec"
	"strings"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/image"
	"github.com/docker/docker/client"
	"github.com/projectdiscovery/gozero/types"
)

// DockerConfiguration represents the configuration for Docker sandbox
type DockerConfiguration struct {
	Image           string            // Docker image to use (e.g., "ubuntu:20.04", "alpine:latest")
	WorkingDir      string            // Working directory inside container
	Environment     map[string]string // Environment variables
	NetworkMode     string            // Network mode (bridge, host, etc.)
	NetworkDisabled bool              // Disable networking entirely
	User            string            // User to run as inside container
	Memory          string            // Memory limit (e.g., "512m", "1g")
	CPULimit        string            // CPU limit (e.g., "0.5", "1.0")
	Timeout         time.Duration     // Command timeout
	Remove          bool              // Whether to remove container after execution
}

// SandboxDocker implements the Sandbox interface using Docker containers
type SandboxDocker struct {
	config       *DockerConfiguration
	dockerClient *client.Client
}

// NewDockerSandbox creates a new Docker-based sandbox
func NewDockerSandbox(ctx context.Context, config *DockerConfiguration) (*SandboxDocker, error) {
	// Check if Docker is available
	if ok, err := isDockerInstalled(ctx); err != nil || !ok {
		return nil, fmt.Errorf("docker not available: %w", err)
	}

	// Create Docker client
	dockerClient, err := client.NewClientWithOpts(
		client.WithAPIVersionNegotiation(),
		client.FromEnv,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create docker client: %w", err)
	}

	// Test Docker connection
	_, err = dockerClient.Ping(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to docker daemon: %w", err)
	}

	// Validate required configuration
	if config.Image == "" {
		return nil, fmt.Errorf("docker image must be specified")
	}
	if config.WorkingDir == "" {
		return nil, fmt.Errorf("working directory must be specified")
	}
	if config.Timeout == 0 {
		config.Timeout = 30 * time.Second
	}
	if config.Remove {
		config.Remove = true // Default to removing containers
	}

	return &SandboxDocker{
		config:       config,
		dockerClient: dockerClient,
	}, nil
}

// runCommand executes a command in the Docker container with the given command parts
func (s *SandboxDocker) runCommand(ctx context.Context, cmdParts []string, command string, createFile bool, fileContent string) (*types.Result, error) {
	if len(cmdParts) == 0 {
		return nil, fmt.Errorf("empty command")
	}

	// Create a new context with timeout
	runCtx, cancel := context.WithTimeout(ctx, s.config.Timeout)
	defer cancel()

	// Prepare environment variables
	env := []string{}
	for key, value := range s.config.Environment {
		env = append(env, fmt.Sprintf("%s=%s", key, value))
	}

	// If we need to create a file, modify the command to create it first
	finalCmd := cmdParts
	if createFile && len(fileContent) > 0 {
		// Generate a temporary filename
		tmpFileName := fmt.Sprintf("/tmp/gozero_script_%d.sh", time.Now().UnixNano())

		// Create a script that writes the file content and then executes it
		scriptContent := fmt.Sprintf(`#!/bin/sh
cat > %s << 'EOF'
%s
EOF
chmod +x %s
exec %s
`, tmpFileName, fileContent, tmpFileName, tmpFileName)

		// Create a command that writes the script and executes it
		finalCmd = []string{"/bin/sh", "-c", scriptContent}
	}

	// Create container configuration
	containerConfig := &container.Config{
		Image:        s.config.Image,
		Cmd:          finalCmd,
		WorkingDir:   s.config.WorkingDir,
		Env:          env,
		User:         s.config.User,
		AttachStdout: true,
		AttachStderr: true,
	}

	// Create host configuration
	hostConfig := &container.HostConfig{
		AutoRemove: false, // Don't auto-remove so we can get logs
	}

	// Set network configuration
	if s.config.NetworkDisabled {
		hostConfig.NetworkMode = "none"
	} else if s.config.NetworkMode != "" {
		hostConfig.NetworkMode = container.NetworkMode(s.config.NetworkMode)
	}

	// Set resource limits if specified
	if s.config.Memory != "" {
		hostConfig.Memory = parseMemoryLimit(s.config.Memory)
	}

	// Pull image if it doesn't exist locally
	err := s.pullImageIfNeeded(runCtx, s.config.Image)
	if err != nil {
		return nil, fmt.Errorf("failed to pull image %s: %w", s.config.Image, err)
	}

	// Create container
	createResp, err := s.dockerClient.ContainerCreate(runCtx, containerConfig, hostConfig, nil, nil, "")
	if err != nil {
		return nil, fmt.Errorf("failed to create container: %w", err)
	}

	containerID := createResp.ID

	// Start container
	err = s.dockerClient.ContainerStart(runCtx, containerID, container.StartOptions{})
	if err != nil {
		_ = s.dockerClient.ContainerRemove(runCtx, containerID, container.RemoveOptions{Force: true})
		return nil, fmt.Errorf("failed to start container: %w", err)
	}

	// Wait for container to finish
	waitCh, errCh := s.dockerClient.ContainerWait(runCtx, containerID, container.WaitConditionNotRunning)

	select {
	case err := <-errCh:
		_ = s.dockerClient.ContainerRemove(runCtx, containerID, container.RemoveOptions{Force: true})
		return nil, fmt.Errorf("container wait error: %w", err)
	case result := <-waitCh:
		// Get container logs
		logs, err := s.dockerClient.ContainerLogs(runCtx, containerID, container.LogsOptions{
			ShowStdout: true,
			ShowStderr: true,
		})
		if err != nil {
			_ = s.dockerClient.ContainerRemove(runCtx, containerID, container.RemoveOptions{Force: true})
			return nil, fmt.Errorf("failed to get container logs: %w", err)
		}
		defer func() {
			_ = logs.Close()
		}()

		// Read logs
		logData := make([]byte, 1024*1024) // 1MB buffer
		n, err := logs.Read(logData)
		if err != nil && err.Error() != "EOF" {
			_ = s.dockerClient.ContainerRemove(runCtx, containerID, container.RemoveOptions{Force: true})
			return nil, fmt.Errorf("failed to read container logs: %w", err)
		}

		// Create result
		cmdResult := &types.Result{
			Command: command,
		}
		cmdResult.Stdout.Write(logData[:n])

		// Set exit code
		if result.StatusCode != 0 {
			cmdResult.SetExitError(&exec.ExitError{})
		}

		// Always clean up container manually
		_ = s.dockerClient.ContainerRemove(runCtx, containerID, container.RemoveOptions{Force: true})

		return cmdResult, nil
	}
}

// Run executes a command in the Docker container (synchronous execution)
func (s *SandboxDocker) Run(ctx context.Context, cmd string) (*types.Result, error) {
	// Parse command into parts
	cmdParts := strings.Fields(cmd)
	return s.runCommand(ctx, cmdParts, cmd, false, "")
}

// RunScript executes a script in the Docker container
func (s *SandboxDocker) RunScript(ctx context.Context, source string, interpreter string) (*types.Result, error) {
	return s.RunSource(ctx, source, interpreter)
}

// RunSource writes source code to a temporary file inside the container and executes it
func (s *SandboxDocker) RunSource(ctx context.Context, source string, interpreter string) (*types.Result, error) {
	// Generate a temporary filename
	tmpFileName := fmt.Sprintf("/tmp/gozero_script_%d", time.Now().UnixNano())

	// Check if source has a shebang - if so, use it instead of the interpreter
	// Otherwise, use the provided interpreter
	execCmd := fmt.Sprintf("%s %s", interpreter, tmpFileName)
	if strings.HasPrefix(source, "#!") {
		// Source has shebang, let it execute directly
		execCmd = tmpFileName
	}

	// Create a script that writes the source content and then executes it
	scriptContent := fmt.Sprintf(`cat > %s << 'EOF'
%s
EOF
chmod +x %s
exec %s
`, tmpFileName, source, tmpFileName, execCmd)

	log.Println(tmpFileName)
	log.Println(scriptContent)

	// Execute the script directly
	cmdParts := []string{"/bin/sh", "-c", scriptContent}
	return s.runCommand(ctx, cmdParts, fmt.Sprintf("exec %s", tmpFileName), false, "")
}

// Start is not implemented for Docker sandbox as it's stateless
func (s *SandboxDocker) Start() error {
	return ErrNotImplemented
}

// Wait is not implemented for Docker sandbox as it's stateless
func (s *SandboxDocker) Wait() error {
	return ErrNotImplemented
}

// Stop is not implemented for Docker sandbox as it's stateless
func (s *SandboxDocker) Stop() error {
	return ErrNotImplemented
}

// Clear cleans up Docker resources (containers, images, etc.)
func (s *SandboxDocker) Clear() error {
	// For now, we don't need to clean up anything as containers are removed after execution
	// In the future, we could add cleanup of unused images or containers
	return nil
}

// isDockerInstalled checks if Docker is installed and available by executing docker info
func isDockerInstalled(ctx context.Context) (bool, error) {
	cmd := exec.CommandContext(ctx, "docker", "info")
	err := cmd.Run()
	if err != nil {
		return false, err
	}
	return true, nil
}

// parseMemoryLimit parses memory limit string (e.g., "512m", "1g") to bytes
func parseMemoryLimit(memory string) int64 {
	if memory == "" {
		return 0
	}

	// Basic parsing - in production, use a proper library
	// This is a simplified implementation
	memory = strings.ToLower(strings.TrimSpace(memory))

	var multiplier int64 = 1
	if strings.HasSuffix(memory, "g") {
		multiplier = 1024 * 1024 * 1024
		memory = strings.TrimSuffix(memory, "g")
	} else if strings.HasSuffix(memory, "m") {
		multiplier = 1024 * 1024
		memory = strings.TrimSuffix(memory, "m")
	} else if strings.HasSuffix(memory, "k") {
		multiplier = 1024
		memory = strings.TrimSuffix(memory, "k")
	}

	// Parse the numeric part
	var value int64
	_, _ = fmt.Sscanf(memory, "%d", &value)
	return value * multiplier
}

// pullImageIfNeeded pulls the Docker image if it doesn't exist locally
func (s *SandboxDocker) pullImageIfNeeded(ctx context.Context, imageName string) error {
	// Check if image exists locally
	_, _, err := s.dockerClient.ImageInspectWithRaw(ctx, imageName)
	if err == nil {
		// Image exists locally, no need to pull
		return nil
	}

	// Image doesn't exist, pull it
	reader, err := s.dockerClient.ImagePull(ctx, imageName, image.PullOptions{})
	if err != nil {
		return fmt.Errorf("failed to pull image: %w", err)
	}
	defer func() {
		_ = reader.Close()
	}()

	// Read the pull progress to completion
	buf := make([]byte, 1024)
	for {
		_, readErr := reader.Read(buf)
		if readErr == nil {
			continue
		}
		// EOF is expected when pull completes successfully
		if readErr.Error() != "EOF" {
			return fmt.Errorf("failed to complete image pull: %w", readErr)
		}
		break
	}

	return nil
}
