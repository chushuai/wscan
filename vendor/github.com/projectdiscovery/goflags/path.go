package goflags

import (
	"os"
	"path/filepath"
	"strings"

	folderutil "github.com/projectdiscovery/utils/folder"
)

var oldAppConfigDir = filepath.Join(folderutil.HomeDirOrDefault("."), ".config", getToolName())

// GetConfigFilePath returns the config file path
func (flagSet *FlagSet) GetConfigFilePath() (string, error) {
	// return configFilePath if already set
	if flagSet.configFilePath != "" {
		return flagSet.configFilePath, nil
	}
	return filepath.Join(folderutil.AppConfigDirOrDefault(".", getToolName()), "config.yaml"), nil
}

// GetToolConfigDir returns the config dir path of the tool
func (flagset *FlagSet) GetToolConfigDir() string {
	cfgFilePath, _ := flagset.GetConfigFilePath()
	return filepath.Dir(cfgFilePath)
}

// SetConfigFilePath sets custom config file path
func (flagSet *FlagSet) SetConfigFilePath(filePath string) {
	flagSet.configFilePath = filePath
}

// getToolName returns the name of the tool
func getToolName() string {
	appName := filepath.Base(os.Args[0])
	return strings.TrimSuffix(appName, filepath.Ext(appName))
}
