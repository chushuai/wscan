package rsync

import (
	"bytes"
)

type Sender struct {
	Conn    *Conn
	Module  string
	Path    string
	Seed    int32
	LVer    int32
	RVer    int32
	Storage FS
}

func (s *Sender) SendFileList() error {
	list, err := s.Storage.List()
	if err != nil {
		return err
	}

	// Send list to receiver
	var last *FileInfo
	for _, f := range list {
		var flags byte

		if bytes.Equal(f.Path, []byte(".")) {
			if f.Mode.IsDIR() {
				flags |= FLIST_TOP_LEVEL
			}
		}

		lPathCount := 0
		if last != nil {
			lPathCount = longestMatch(last.Path, f.Path)
			if lPathCount > 255 { // Limit to 255 chars
				lPathCount = 255
			}
			if lPathCount > 0 {
				flags |= FLIST_NAME_SAME
			}
			if last.Mode == f.Mode {
				flags |= FLIST_MODE_SAME
			}
			if last.Mtime == f.Mtime {
				flags |= FLIST_TIME_SAME
			}
			//
			//
			//
		}

		rPathCount := int32(len(f.Path) - lPathCount)
		if rPathCount > 255 {
			flags |= FLIST_NAME_LONG
		}

		/* we must make sure we don't send a zero flags byte or the other
		   end will terminate the flist transfer */
		if flags == 0 && !f.Mode.IsDIR() {
			flags |= 1 << 0
		}
		if flags == 0 {
			flags |= FLIST_NAME_LONG
		}
		/* Send flags */
		if err := s.Conn.WriteByte(flags); err != nil {
			return err
		}

		/* Send len of path, and bytes of path */
		if flags&FLIST_NAME_SAME != 0 {
			if err = s.Conn.WriteByte(flags); err != nil {
				return err
			}
		}

		if flags&FLIST_NAME_LONG != 0 {
			if err = s.Conn.WriteInt(rPathCount); err != nil {
				return err
			}
		} else {
			if err = s.Conn.WriteByte(byte(rPathCount)); err != nil {
				return err
			}
		}

		if _, err = s.Conn.Write(f.Path[lPathCount:]); err != nil {
			return err
		}

		/* Send size of file */
		if err = s.Conn.WriteLong(f.Size); err != nil {
			return err
		}

		/* Send Mtime, GID, UID, RDEV if needed */
		if flags&FLIST_TIME_SAME == 0 {
			if err = s.Conn.WriteInt(f.Mtime); err != nil {
				return err
			}
		}
		if flags&FLIST_MODE_SAME == 0 {
			if err = s.Conn.WriteInt(int32(f.Mode)); err != nil {
				return err
			}
		}
		// TODO: UID GID RDEV

		// TODO: Send symlink

		// TODO: if always_checksum?

		//nolint
		last = &f
	}
	return nil
}

func (s *Sender) Generator(_ FileList) error {
	for {
		index, err := s.Conn.ReadInt()
		if err != nil {
			return err
		} else if index == INDEX_END {
			break
		}

		// Receive block checksum from receiver
		count, err := s.Conn.ReadInt()
		if err != nil {
			return err
		}

		blen, err := s.Conn.ReadInt()
		if err != nil {
			return err
		}

		s2len, err := s.Conn.ReadInt()
		if err != nil {
			return err
		}

		remainder, err := s.Conn.ReadInt()
		if err != nil {
			return err
		}

		// sums := make([]SumChunk, 0, count)

		var (
			i      int32
			offset int64
		)

		for ; i < count; i++ {
			sum1, err := s.Conn.ReadInt() // sum1:
			if err != nil {
				return err
			}

			sum2 := make([]byte, 16)
			if _, err := s.Conn.Read(sum2); err != nil {
				return err
			}

			chunk := new(SumChunk)
			chunk.Sum1 = uint32(sum1)
			chunk.Sum2 = sum2
			chunk.FileOffset = offset

			if i == count-1 && remainder != 0 {
				chunk.ChunkLen = uint(remainder)
			} else {
				chunk.ChunkLen = uint(blen)
			}
			offset += int64(chunk.ChunkLen)
			// sums = append(sums)
		}
		result := new(SumStruct)
		result.FileLen = uint64(offset)
		result.Count = uint64(count)
		result.BlockLen = uint64(blen)
		result.Sum2Len = uint64(s2len)
		result.Remainder = uint64(remainder)
	}
	if err := s.FileUploader(); err != nil {
		return err
	}
	return nil
}

func (s *Sender) FileUploader() error {
	panic("Not implemented yet")
}

func (s *Sender) FinalPhase() error {
	panic("Not implemented yet")
}

func (s *Sender) Sync() error {
	panic("Not implemented yet")
}
