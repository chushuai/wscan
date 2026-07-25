// Copyright © 2016 Zlatko Čalušić
//
// Use of this source code is governed by an MIT-style license that can be found in the LICENSE file.

package sysinfo

import (
	"os"
	"strings"
)

// Read one-liner text files, strip newline.
func slurpFile(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}

	// Trim spaces & \u0000 \uffff
	return strings.Trim(string(data), " \r\n\t\u0000\uffff")
}

// Write one-liner text files, add newline, ignore errors (best effort).
func spewFile(path string, data string, perm os.FileMode) {
	_ = os.WriteFile(path, []byte(data+"\n"), perm)
}
