/**
* @Author: shaochuyu
* @Date: 5/7/2022 11:30
 */
package crawler

import (
	"bytes"
	"io"
)

type Body struct {
	buffer       *bytes.Buffer
	bufferBackup *bytes.Buffer
}

func (b *Body) Bytes() []byte {
	return b.buffer.Bytes()
}

func (b *Body) Cap() int {
	return b.buffer.Cap()
}

func (b *Body) Close() error {
	b.buffer.Reset()
	b.bufferBackup.Reset()
	return nil
}

func (b *Body) Len() int {
	return b.buffer.Len()
}

func (b *Body) Read(p []byte) (int, error) {
	return b.buffer.Read(p)
}

func (b *Body) UnRead() {
	if b.bufferBackup != nil {
		b.buffer.Reset()
		b.buffer.Write(b.bufferBackup.Bytes())
		b.bufferBackup.Reset()
	}
}

// 方法将备份缓冲区的数据写入 w 中，并返回写入的字节数和 nil。在写入之前，会先将缓冲区的数据复制到备份缓冲区。
func (b *Body) WriteTo(w io.Writer) (int64, error) {
	if b.bufferBackup == nil {
		b.bufferBackup = bytes.NewBuffer(make([]byte, 0, b.buffer.Len()))
	}
	b.bufferBackup.Reset()
	b.bufferBackup.Write(b.buffer.Bytes())
	n, err := b.bufferBackup.WriteTo(w)
	return n, err
}
