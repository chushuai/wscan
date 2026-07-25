package console

import (
	"log"
	"os"
)

var (
	stderrLogger = log.Default() // the default logger output to stderr
	stdoutLogger = log.New(os.Stdout, "", log.LstdFlags)

	defaultStdPrinter Printer = &StdPrinter{
		StdoutPrint: func(s string) { stdoutLogger.Print(s) },
		StderrPrint: func(s string) { stderrLogger.Print(s) },
	}
)

// StdPrinter implements the console.Printer interface
// that prints to the stdout or stderr.
type StdPrinter struct {
	StdoutPrint func(s string)
	StderrPrint func(s string)
}

// Log prints s to the stdout.
func (p StdPrinter) Log(s string) {
	p.StdoutPrint(s)
}

// Warn prints s to the stderr.
func (p StdPrinter) Warn(s string) {
	p.StderrPrint(s)
}

// Error prints s to the stderr.
func (p StdPrinter) Error(s string) {
	p.StderrPrint(s)
}
