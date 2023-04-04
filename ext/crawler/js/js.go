/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package js

import (
	"bytes"
	"io"
	"io/fs"
	"net/http"
	"sync"
	"time"
)

type _escFile struct {
	compressed string
	size       int64
	modtime    int64
	local      string
	isDir      bool
	once       sync.Once
	data       []uint8
	name       string
}

type httpFile struct {
	*bytes.Reader
	*_escFile
}

func (httpFile) Close() error {
	return nil
}
func (httpFile) File() (http.File, error) {
	return nil, nil
}
func (httpFile) IsDir() bool {
	return false
}
func (httpFile) Len() int {
	return 0
}
func (httpFile) ModTime() time.Time {
	return time.Time{}
}
func (httpFile) Mode() uint32 {
	return 0
}
func (httpFile) Name() string {
	return ""
}
func (httpFile) Read([]uint8) (int, error) {
	return 0, nil
}
func (httpFile) ReadAt([]uint8, int64) (int, error) {
	return 0, nil
}
func (httpFile) ReadByte() (uint8, error) {
	return 0, nil
}

func (httpFile) ReadRune() (int32, int, error) {
	return 0, 0, nil
}
func (httpFile) Readdir(int) ([]fs.FileInfo, error) {
	return nil, nil
}
func (httpFile) Reset([]uint8) {

}
func (httpFile) Seek(int64, int) (int64, error) {
	return 0, nil
}
func (httpFile) Stat() (fs.FileInfo, error) {
	return nil, nil
}
func (httpFile) Sys() interface{} {
	return nil
}
func (httpFile) UnreadByte() error {
	return nil
}
func (httpFile) UnreadRune() error {
	return nil
}
func (httpFile) WriteTo(io.Writer) (int64, error) {
	return 0, nil
}
