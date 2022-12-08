package file

import (
	"os"
	"path/filepath"
)

func GetFiles(path string) ([]string, error) {
	var fileList []string
	err := filepath.Walk(path, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			fileList = append(fileList, path)
		}
		return nil
	})
	if err != nil {
		return fileList, err
	}
	return fileList, nil
}
