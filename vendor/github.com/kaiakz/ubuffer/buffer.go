package ubuffer

import (
	"bytes"
	"io/ioutil"
	"os"
)

const MEMSIZE = 50 * (1 << 20)

type Buffer struct {
	mem *bytes.Buffer
	swap *os.File
}

func NewBuffer(cap int64) *Buffer {
	var (
		mem = new(bytes.Buffer)
		swap *os.File = nil
		err error
	)
	if cap > MEMSIZE {
		swap, err = ioutil.TempFile("", "ubuffer-*")
		if err != nil || swap == nil || swap.Close() != nil{
			return nil
		}
		swap, err = os.OpenFile(swap.Name(), os.O_APPEND | os.O_RDWR, 0644)
		if err != nil {
			return nil
		}
	}
	return &Buffer{
		mem: mem,
		swap: swap,
	}
}

func (buffer *Buffer) Finalize() error {
	buffer.mem.Reset()
	if buffer.swap != nil {
		err := buffer.swap.Close()
		if err != nil {
			return err
		}
		return os.Remove(buffer.swap.Name())
	}
	return nil
}

func (buffer *Buffer) Write(p []byte) (n int, err error) {
	if buffer.swap != nil {
		return buffer.swap.Write(p[:])
	}
	return buffer.mem.Write(p[:])
}

func (buffer *Buffer) Read(p []byte) (n int, err error) {
	if buffer.swap != nil {
		return buffer.swap.Read(p[:])
	}
	return buffer.mem.Read(p[:])
}

func (buffer *Buffer) Seek(offset int64, whence int) (ret int64, err error) {
	if buffer.swap != nil {
		return buffer.swap.Seek(offset, whence)
	}
	return 0, nil
}