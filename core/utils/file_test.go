/**
2 * @Author: shaochuyu
 * @Date: 1/21/24
*/

package utils

import (
	"fmt"
	"os"
	"testing"
)

func TestGetAllFilesRecursive(t *testing.T) {
	// Create a temporary directory structure for testing
	tmpDir, err := os.MkdirTemp("", "test_get_all_files_*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	// Create subdirectories and files
	subDir := tmpDir + "/subdir"
	if err := os.MkdirAll(subDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tmpDir+"/file1.txt", []byte("hello"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(subDir+"/file2.txt", []byte("world"), 0644); err != nil {
		t.Fatal(err)
	}

	files, err := GetAllFiles(tmpDir)
	if err != nil {
		t.Fatal(err)
	}

	if len(files) < 2 {
		t.Errorf("expected at least 2 files, got %d", len(files))
	}

	// Check no duplicates
	count := 0
	seen := make(map[string]struct{})
	for _, f := range files {
		if _, ok := seen[f]; ok {
			count += 1
		} else {
			seen[f] = struct{}{}
		}
	}

	fmt.Println("files= ", len(files), count)

	if count > 0 {
		t.Errorf("found %d duplicate file paths", count)
	}
}
