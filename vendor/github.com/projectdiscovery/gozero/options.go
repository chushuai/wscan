package gozero

type Options struct {
	Engines                  []string
	Args                     []string
	engine                   string
	PreferStartProcess       bool
	Sandbox                  bool
	EarlyCloseFileDescriptor bool
}
