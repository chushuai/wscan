package rsync

import (
	"bytes"
	"os"
)

type FileInfo struct {
	Path  []byte
	Size  int64
	Mtime int32
	Mode  FileMode
}

// For unix/linux
type FileMode uint32

// reference: os/types.go
func NewFileMode(mode os.FileMode) FileMode {
	m := FileMode(mode & 0o777)
	// TODO: supports symlink
	if mode.IsRegular() {
		return m | S_IFREG
	}

	types := map[uint32]FileMode{
		0:  S_IFDIR,
		4:  S_IFLNK,
		5:  S_IFBLK,
		6:  S_IFIFO,
		7:  S_IFSOCK,
		10: S_IFCHR,
	}
	for i, t := range types {
		if m&(1<<uint(32-1-i)) != 0 {
			m |= t
		}
	}

	return m
}

func (m FileMode) IsREG() bool {
	return (m & S_IFMT) == S_IFREG
}

func (m FileMode) IsDIR() bool {
	return (m & S_IFMT) == S_IFDIR
}

func (m FileMode) IsBLK() bool {
	return (m & S_IFMT) == S_IFBLK
}

func (m FileMode) IsLNK() bool {
	return (m & S_IFMT) == S_IFLNK
}

func (m FileMode) IsFIFO() bool {
	return (m & S_IFMT) == S_IFIFO
}

func (m FileMode) IsSOCK() bool {
	return (m & S_IFMT) == S_IFSOCK
}

// Return only unix permission bits
func (m FileMode) Perm() FileMode {
	return m & 0o777
}

// Convert to os.FileMode
func (m FileMode) Convert() os.FileMode {
	mode := os.FileMode(m & 0o777)
	switch m & S_IFMT {
	case S_IFREG:
		// For regular files, none will be set.
		break
	case S_IFDIR:
		mode |= os.ModeDir
	case S_IFLNK:
		mode |= os.ModeSymlink
	case S_IFBLK:
		mode |= os.ModeDevice
	case S_IFSOCK:
		mode |= os.ModeSocket
	case S_IFIFO:
		mode |= os.ModeNamedPipe
	case S_IFCHR:
		mode |= os.ModeCharDevice
	default:
		mode |= os.ModeIrregular
	}
	return mode
}

// strmode
func (m FileMode) String() string {
	chars := []byte("-rwxrwxrwx")
	switch m & S_IFMT {
	case S_IFREG:
		break
	case S_IFDIR:
		chars[0] = 'd'
	case S_IFLNK:
		chars[0] = 'l'
	case S_IFBLK:
		chars[0] = 'b'
	case S_IFSOCK:
		chars[0] = 's'
	case S_IFIFO:
		chars[0] = 'p'
	case S_IFCHR:
		chars[0] = 'c'
	default:
		chars[0] = '?'
	}
	for i := 0; i < 9; i++ {
		if m&(1<<i) == 0 {
			chars[9-i] = '-'
		}
	}
	return string(chars)
}

type FileList []FileInfo

func (L FileList) Len() int {
	return len(L)
}

func (L FileList) Less(i, j int) bool {
	return bytes.Compare(L[i].Path, L[j].Path) == -1
}

func (L FileList) Swap(i, j int) {
	L[i], L[j] = L[j], L[i]
}

/*
	Diff two sorted rsync file list, return their difference

list NEW: only R has.
list OLD: only L has.
*/
func (L FileList) Diff(R FileList) (newitems []int, olditems []int) {
	newitems = make([]int, 0, len(R))
	olditems = make([]int, 0, len(L))
	i := 0 // index of L
	j := 0 // index of R

	for i < len(L) && j < len(R) {
		// The result will be 0 if a==b, -1 if a < b, and +1 if a > b.
		// Compare their paths by bytes.Compare
		// The result will be 0 if a==b, -1 if a < b, and +1 if a > b
		// If 1, B doesn't have
		// If 0, A & B have
		// If -1, A doesn't have
		switch bytes.Compare(L[i].Path, R[j].Path) {
		case 0:
			if L[i].Mtime != R[j].Mtime || L[i].Size != R[j].Size {
				newitems = append(newitems, j)
			}
			i++
			j++
		case 1:
			newitems = append(newitems, j)
			j++
		case -1:
			olditems = append(olditems, i)
			i++
		}
	}

	// Handle remains
	for ; i < len(L); i++ {
		olditems = append(olditems, i)
	}
	for ; j < len(R); j++ {
		newitems = append(newitems, j)
	}

	return newitems, olditems
}
