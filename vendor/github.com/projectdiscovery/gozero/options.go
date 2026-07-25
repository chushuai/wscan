package gozero

type Options struct {
	Engines                  []string
	Args                     []string
	engine                   string
	PreferStartProcess       bool
	Sandbox                  bool
	EarlyCloseFileDescriptor bool
	// When Debug Mode is set to true, Output result will contain
	// more debug information
	DebugMode bool
}
