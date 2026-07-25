//go:build windows

package sandbox

import (
	"bytes"
	"context"
	"encoding/xml"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"

	"github.com/projectdiscovery/gozero/types"
)

const DefaultMountPoint = `C:\Users\WDAGUtilityAccount\Desktop`

type Value string

const (
	Enable  Value = "Enable"
	Disable Value = "Disable"
	Default Value = "Default"
)

type Configuration struct {
	MappedFolders   MappedFolders `xml:"MappedFolders"`
	Networking      Value         `xml:"Networking"`
	LogonCommands   LogonCommands `xml:"LogonCommand,omitempty"`
	VirtualGPU      Value         `xml:"vGPU"`
	ProtectedClient Value         `xml:"ProtectedClient"`
	MemoryInMB      int           `xml:"MemoryInMB"`
	IPs             IPS           `xml:"Ips,omitempty"`
	DisableFirewall bool          `xml:"-"`
}

type MappedFolders struct {
	MappedFolder []MappedFolder `xml:"MappedFolder"`
}

type LogonCommands struct {
	Command []string `xml:"Command,omitempty"`
}

type IPS struct {
	IP []string `xml:"IP,omitempty"`
}

type MappedFolder struct {
	HostFolder    string `xml:"HostFolder"`
	SandboxFolder string `xml:"SandboxFolder,omitempty"`
	ReadOnly      bool   `xml:"ReadOnly,omitempty"`
}

// Sandbox native on windows
type SandboxWindows struct {
	Config   *Configuration
	confFile string
	instance *exec.Cmd
	stdout   bytes.Buffer
	stderr   bytes.Buffer
}

// New sandbox with the given configuration
func New(ctx context.Context, config *Configuration) (Sandbox, error) {
	if ok, err := isInstalled(ctx); err != nil || !ok {
		return nil, err
	}

	sharedFolder, err := os.MkdirTemp("", "")
	if err != nil {
		return nil, err
	}

	sharedFolder = filepath.Join(sharedFolder, "gozero")

	if err := os.MkdirAll(sharedFolder, 0600); err != nil {
		return nil, err
	}

	config.MappedFolders.MappedFolder = append(config.MappedFolders.MappedFolder, MappedFolder{
		HostFolder: sharedFolder,
	})

	if config.DisableFirewall {
		config.LogonCommands.Command = append(config.LogonCommands.Command,
			"netsh advfirewall set allprofiles state off",
		)
	}
	// collect all the callback ips
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	for _, addr := range addresses {
		config.IPs.IP = append(config.IPs.IP, addr.String())
	}

	data, err := xml.Marshal(config)
	if err != nil {
		return nil, err
	}
	confFile := filepath.Join(sharedFolder, "config.wsb")
	if err := os.WriteFile(confFile, data, 0600); err != nil {
		return nil, err
	}

	s := &SandboxWindows{Config: config, confFile: confFile}
	s.instance = exec.CommandContext(ctx, "WindowsSandbox.exe", s.confFile)
	s.instance.Stdout = &s.stdout
	s.instance.Stderr = &s.stderr

	return s, nil
}

func (s *SandboxWindows) Run(ctx context.Context, cmd string) (*types.Result, error) {
	return nil, ErrAgentRequired
}

// RunScript executes a script or source code in the sandbox
func (s *SandboxWindows) RunScript(ctx context.Context, source string) (*types.Result, error) {
	return nil, ErrNotImplemented
}

// RunSource writes source code to a temporary file, executes it with proper permissions, and cleans up
func (s *SandboxWindows) RunSource(ctx context.Context, source string, interpreter string) (*types.Result, error) {
	return nil, ErrNotImplemented
}

// Start the instance
func (s *SandboxWindows) Start() error {
	return s.instance.Start()
}

// Wait for the instance
func (s *SandboxWindows) Wait() error {
	return s.instance.Wait()
}

// Stop the instance
func (s *SandboxWindows) Stop() error {
	err := s.instance.Cancel()
	if err != nil {
		return err
	}
	s.instance = nil
	return nil
}

// Clear the instance after stop
func (s *SandboxWindows) Clear() error {
	if err := s.Stop(); err != nil {
		return err
	}
	if err := os.RemoveAll(s.confFile); err != nil {
		return err
	}
	return nil
}

func shellExec(ctx context.Context, args ...string) (string, string, error) {
	powershellPath, err := exec.LookPath("powershell")
	if err != nil {
		return "", "", err
	}
	cmd := exec.CommandContext(ctx, powershellPath, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err = cmd.Run()
	return stdout.String(), stderr.String(), err
}

func isEnabled(ctx context.Context) (bool, error) {
	stdout, _, err := shellExec(ctx, "Get-WindowsOptionalFeature", "-FeatureName", `"Containers-DisposableClientVM"`, "-Online")
	if err != nil {
		return false, err
	}

	return regexp.MatchString(`(?m)State\s*:\s*Enabled`, stdout)
}

func isInstalled(ctx context.Context) (bool, error) {
	_, err := exec.LookPath("WindowsSandbox.exe")
	if err != nil {
		return false, err
	}
	return true, nil
}

func activate(ctx context.Context) (bool, error) {
	_, _, err := shellExec(ctx, "Enable-WindowsOptionalFeature", "-FeatureName", `"Containers-DisposableClientVM"`, "-NoRestart", "True")
	if err != nil {
		return false, err
	}

	return true, nil
}

func deactivate(ctx context.Context) (bool, error) {
	_, _, err := shellExec(ctx, "Disable-WindowsOptionalFeature", "-FeatureName", `"Containers-DisposableClientVM"`, "-Online")
	if err != nil {
		return false, err
	}

	return true, nil
}
