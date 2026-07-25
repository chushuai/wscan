package rsync

import (
	"io"
)

type FileMetadata struct {
	Mtime int32
	Mode  FileMode
}

// File System: need to handle all type of files: regular, folder, symlink, etc
type FS interface {
	Put(fileName string, content io.Reader, fileSize int64, metadata FileMetadata) (written int64, err error)
	// Get(fileName string, metadata FileMetadata) (File, error)
	Delete(fileName string, mode FileMode) error
	List() (FileList, error)
	// Stats() (seekable bool)
}

// Interface: Read, ReadAt, Seek, Close
type File interface {
	io.Reader
	io.ReaderAt
	io.Seeker
	io.Closer
}
