/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package utils

import (
	"bufio"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
)

func FileExists(path string) bool {
	// Get the file info for the path
	_, err := os.Stat(path)
	if os.IsNotExist(err) {
		return false
	}
	// Return true if the path exists and is a regular file
	return err == nil && !IsDir(path)
}

func IsDir(path string) bool {
	// Get the file info for the path
	info, err := os.Stat(path)
	if err != nil {
		return false
	}

	// Check if the file info indicates that the path is a directory
	return info.IsDir()
}

func GetTempFilePath(prefix string, suffix string) (string, error) {
	// Get the system's temporary directory path
	tempDir := os.TempDir()

	// Generate a random filename with the given prefix and suffix
	randName := fmt.Sprintf("%s%d%s", prefix, rand.Int(), suffix)

	// Join the temporary directory and the random filename to create the full path
	fullPath := filepath.Join(tempDir, randName)

	// Return the full path
	return fullPath, nil
}

func IsDynamicFileExt(filename string) bool {
	// Define a list of dynamic file extensions
	dynamicExts := []string{".php", ".jsp", ".asp", ".aspx", ".cgi", ".pl", ".py", ".rb"}

	// Check if the file extension is in the list of dynamic extensions
	for _, ext := range dynamicExts {
		if strings.HasSuffix(filename, ext) {
			return true
		}
	}

	// If the file extension is not in the list of dynamic extensions, return false
	return false
}

func GetExeRelativePath(relPath string) (string, error) {
	// 获取可执行文件的绝对路径
	exePath, err := os.Executable()
	if err != nil {
		return "", err
	}

	// 获取包含可执行文件的目录
	exeDir := filepath.Dir(exePath)

	/// 获取相对路径参数的绝对路径
	absPath, err := filepath.Abs(filepath.Join(exeDir, relPath))
	if err != nil {
		return "", err
	}

	// Get the relative path of the absolute path
	relPath, err = filepath.Rel(exeDir, absPath)
	if err != nil {
		return "", err
	}

	// Return the relative path
	return relPath, nil
}

// Reading file and return content as []string
func ReadingLines(filename string) []string {
	var result []string
	file, err := os.Open(filename)
	defer file.Close()
	if err != nil {
		return result
	}

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		val := scanner.Text()
		if val == "" {
			continue
		}
		result = append(result, val)
	}

	if err := scanner.Err(); err != nil {
		return result
	}
	return result
}

func GetAllFiles(rootDir string) ([]string, error) {
	var files []string

	err := filepath.Walk(rootDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			files = append(files, path)
		}
		return nil
	})

	if err != nil {
		return nil, err
	}

	return files, nil
}
