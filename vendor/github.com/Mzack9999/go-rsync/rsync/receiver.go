package rsync

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"log/slog"
	"sort"
	"time"

	"github.com/kaiakz/ubuffer"
)

/*
	Receiver:

1. Receive File list
2. Request files by sending files' index
3. Receive Files, pass the files to Storage
*/
type Receiver struct {
	Conn    *Conn
	Module  string
	Path    string
	Seed    int32
	LVer    int32
	RVer    int32
	Storage FS
	Logger  *slog.Logger
}

// Return a filelist from remote
func (r *Receiver) RecvFileList() (FileList, map[string][]byte, error) {
	filelist := make(FileList, 0, 1*M)
	symlinks := make(map[string][]byte)
	for {
		flags, err := r.Conn.ReadByte()
		if err != nil {
			return filelist, symlinks, err
		}

		if flags == FLIST_END {
			break
		}

		lastIndex := len(filelist) - 1
		var partial, pathlen uint32

		/*
		 * Read our filename.
		 * If we have FLIST_NAME_SAME, we inherit some of the last
		 * transmitted name.
		 * If we have FLIST_NAME_LONG, then the string length is greater
		 * than byte-size.
		 */
		if (flags & FLIST_NAME_SAME) != 0 {
			val, err := r.Conn.ReadByte()
			if err != nil {
				return filelist, symlinks, err
			}
			partial = uint32(val)
		}

		/* Get the (possibly-remaining) filename length. */
		if (flags & FLIST_NAME_LONG) != 0 {
			val, err := r.Conn.ReadInt()
			if err != nil {
				return filelist, symlinks, err
			}
			pathlen = uint32(val) // can't use for rsync 31
		} else {
			val, err := r.Conn.ReadByte()
			if err != nil {
				return filelist, symlinks, err
			}
			pathlen = uint32(val)
		}

		/* Allocate our full filename length. */
		/* FIXME: maximum pathname length. */
		// TODO: if pathlen + particular == 0
		// malloc len error?

		p := make([]byte, pathlen)
		_, err = io.ReadFull(r.Conn, p)
		if err != nil {
			return filelist, symlinks, err
		}

		path := make([]byte, 0, partial+pathlen)
		/* If so, use last */
		if (flags & FLIST_NAME_SAME) != 0 { // FLIST_NAME_SAME
			last := filelist[lastIndex]
			path = append(path, last.Path[0:partial]...)
		}
		path = append(path, p...)

		size, err := r.Conn.ReadVarint()
		if err != nil {
			return filelist, symlinks, err
		}

		/* Read the modification time. */
		var mtime int32
		if (flags & FLIST_TIME_SAME) == 0 {
			mtime, err = r.Conn.ReadInt()
			if err != nil {
				return filelist, symlinks, err
			}
		} else {
			mtime = filelist[lastIndex].Mtime
		}

		/* Read the file mode. */
		var mode FileMode
		if (flags & FLIST_MODE_SAME) == 0 {
			val, err := r.Conn.ReadInt()
			if err != nil {
				return filelist, symlinks, err
			}
			mode = FileMode(val)
		} else {
			mode = filelist[lastIndex].Mode
		}

		// TODO: Sym link
		if ((mode & 32768) != 0) && ((mode & 8192) != 0) {
			sllen, err := r.Conn.ReadInt()
			if err != nil {
				return filelist, symlinks, err
			}
			slink := make([]byte, sllen)
			_, err = io.ReadFull(r.Conn, slink)
			symlinks[string(path)] = slink
			if err != nil {
				return filelist, symlinks, errors.New("failed to read symlink")
			}
		}

		r.Logger.Debug("file list entry received", slog.String("path", string(path)), slog.Uint64("size", uint64(size)), slog.Int64("mtime", int64(mtime)), slog.Any("mode", mode))

		filelist = append(filelist, FileInfo{
			Path:  path,
			Size:  size,
			Mtime: mtime,
			Mode:  mode,
		})
	}

	// Sort the filelist lexicographically
	sort.Sort(filelist)

	return filelist, symlinks, nil
}

// Generator: handle files: if it's a regular file, send its index. Otherwise, put them to Storage
func (r *Receiver) Generator(remoteList FileList, downloadList []int, symlinks map[string][]byte) error {
	emptyBlocks := make([]byte, 16) // 4 + 4 + 4 + 4 bytes, all bytes set to 0
	content := new(bytes.Buffer)

	for _, v := range downloadList {
		if remoteList[v].Mode.IsREG() {
			if err := r.Conn.WriteInt(int32(v)); err != nil {
				r.Logger.Error("Failed to send index", slog.Any("index", v))
				return err
			}

			if _, err := r.Conn.Write(emptyBlocks); err != nil {
				return err
			}
		} else {
			// TODO: Supports more file mode
			// EXPERIMENTAL
			// Handle folders & symbol links
			content.Reset()
			size := remoteList[v].Size
			if remoteList[v].Mode.IsLNK() {
				if _, err := content.Write(symlinks[string(remoteList[v].Path)]); err != nil {
					return err
				}
				size = int64(content.Len())
			}

			if _, err := r.Storage.Put(string(remoteList[v].Path), content, size, FileMetadata{
				Mtime: remoteList[v].Mtime,
				Mode:  remoteList[v].Mode,
			}); err != nil {
				return err
			}
		}
	}

	// Send -1 to finish, then start to download
	if err := r.Conn.WriteInt(INDEX_END); err != nil {
		r.Logger.Error("Failed to send INDEX_END")
		return err
	}
	r.Logger.Debug("request completed")

	startTime := time.Now()
	err := r.FileDownloader(remoteList[:])
	r.Logger.Debug("download completed", slog.Duration("duration", time.Since(startTime)))
	return err
}

// TODO: It is better to update files in goroutine
func (r *Receiver) FileDownloader(localList FileList) error {
	rmd4 := make([]byte, 16)

	for {
		index, err := r.Conn.ReadInt()
		if err != nil {
			return err
		}
		if index == INDEX_END { // -1 means the end of transfer files
			return nil
		}

		count, err := r.Conn.ReadInt() /* block count */
		if err != nil {
			return err
		}

		blen, err := r.Conn.ReadInt() /* block length */
		if err != nil {
			return err
		}

		clen, err := r.Conn.ReadInt() /* checksum length */
		if err != nil {
			return err
		}

		remainder, err := r.Conn.ReadInt() /* block remainder */
		if err != nil {
			return err
		}

		path := localList[index].Path
		r.Logger.Debug("Downloading", slog.String("path", string(path)), slog.Uint64("count", uint64(count)), slog.Uint64("blen", uint64(blen)), slog.Uint64("clen", uint64(clen)), slog.Uint64("remainder", uint64(remainder)), slog.Int64("size", localList[index].Size))

		// If the file is too big to store in memory, creates a temporary file in the directory 'tmp'
		buffer := ubuffer.NewBuffer(localList[index].Size)
		downloadeSize := 0
		bufwriter := bufio.NewWriter(buffer)

		// Create MD4
		//lmd4 := md4.New()
		//if err := binary.Write(lmd4, binary.LittleEndian, r.seed); err != nil {
		//  r.Logger.Error("Failed to compute md4", slog.Error(err))
		//}

		for {
			token, err := r.Conn.ReadInt()
			if err != nil {
				return err
			}

			if token == 0 {
				break
			} else if token < 0 {
				return errors.New("does not support block checksum")
				// Reference
			}

			ctx := make([]byte, token) // FIXME: memory leak?
			_, err = io.ReadFull(r.Conn, ctx)
			if err != nil {
				return err
			}

			downloadeSize += int(token)

			if _, err := bufwriter.Write(ctx); err != nil {
				return err
			}
			//if _, err := lmd4.Write(ctx); err != nil {
			//	return err
			//}
		}
		if bufwriter.Flush() != nil {
			return errors.New("failed to flush buffer")
		}

		// Remote MD4
		// TODO: compare computed MD4 with remote MD4
		_, err = io.ReadFull(r.Conn, rmd4)
		if err != nil {
			return err
		}
		// Compare two MD4
		//if bytes.Compare(rmd4, lmd4.Sum(nil)) != 0 {
		//  r.Logger.Error("Checksum error", slog.String("path", string(path)))
		//}

		// Put file to object Storage
		_, err = buffer.Seek(0, io.SeekStart)
		if err != nil {
			return err
		}

		n, err := r.Storage.Put(string(path), buffer, int64(downloadeSize), FileMetadata{
			Mtime: localList[index].Mtime,
			Mode:  localList[index].Mode,
		})
		if err != nil {
			return err
		}

		if buffer.Finalize() != nil {
			return errors.New("buffer can't be finalized")
		}

		r.Logger.Debug("successfully uploaded", slog.String("path", string(path)), slog.Int64("size", n))
	}
}

// Clean up local files
func (r *Receiver) FileCleaner(localList FileList, deleteList []int) error {
	// Since file list was already sorted, we can iterate it in the reverse direction to traverse the file tree in post-order
	// Thus it always cleans sub-files firstly
	for i := len(deleteList) - 1; i >= 0; i-- {
		fname := string(localList[deleteList[i]].Path)
		err := r.Storage.Delete(fname, localList[deleteList[i]].Mode)
		if err != nil {
			return err
		}

		r.Logger.Debug("Deleted", slog.String("path", fname))
	}
	return nil
}

func (r *Receiver) FinalPhase() error {
	//go func() {
	//	ioerror, err := r.Conn.ReadInt()
	//  r.Logger.Debug("ioerr", slog.Int64("ioerror", ioerror))
	//}()

	err := r.Conn.WriteInt(INDEX_END)
	if err != nil {
		return err
	}
	return r.Conn.WriteInt(INDEX_END)
}

func (r *Receiver) Sync() error {
	defer func() {
		r.Conn.Close() // TODO: How to handle errors from Close
		r.Logger.Debug("task completed")
	}()

	lfiles, err := r.Storage.List()
	if err != nil {
		return err
	}

	rfiles, symlinks, err := r.RecvFileList()
	if err != nil {
		return err
	}
	r.Logger.Debug("remote files count", slog.Int64("count", int64(len(rfiles))))

	ioerr, err := r.Conn.ReadInt()
	if err != nil {
		return err
	}
	r.Logger.Debug("ioerr", slog.Int64("ioerr", int64(ioerr)))

	newfiles, oldfiles := lfiles.Diff(rfiles)
	if len(newfiles) == 0 && len(oldfiles) == 0 {
		r.Logger.Debug("there is nothing to do") // TODO: Return here?
	}

	if err := r.Generator(rfiles[:], newfiles[:], symlinks); err != nil {
		return err
	}
	if err := r.FileCleaner(lfiles[:], oldfiles[:]); err != nil {
		return err
	}
	if err := r.FinalPhase(); err != nil {
		return err
	}
	return nil
}

type SyncPlan struct {
	RemoteFiles      FileList
	LocalFiles       FileList
	AddRemoteFiles   []int
	DeleteLocalFiles []int
	Symlinks         map[string][]byte
}

func (r *Receiver) GetSyncPlan() (*SyncPlan, error) {
	defer func() {
		r.Conn.Close() // TODO: How to handle errors from Close
		r.Logger.Debug("task completed")
	}()

	lfiles, err := r.Storage.List()
	if err != nil {
		return nil, err
	}

	rfiles, symlinks, err := r.RecvFileList()
	if err != nil {
		return nil, err
	}
	r.Logger.Debug("remote files count", slog.Int64("count", int64(len(rfiles))))

	ioerr, err := r.Conn.ReadInt()
	if err != nil {
		return nil, err
	}
	r.Logger.Debug("ioerr", slog.Int64("ioerr", int64(ioerr)))

	newfiles, oldfiles := lfiles.Diff(rfiles)
	if len(newfiles) == 0 && len(oldfiles) == 0 {
		r.Logger.Debug("there is nothing to do") // TODO: Return here?
	}

	if err := r.FinalPhase(); err != nil {
		return nil, err
	}

	return &SyncPlan{
		RemoteFiles:      rfiles,
		LocalFiles:       lfiles,
		AddRemoteFiles:   newfiles,
		DeleteLocalFiles: oldfiles,
		Symlinks:         symlinks,
	}, nil
}

func (r *Receiver) List() (FileList, error) {
	defer func() {
		r.Conn.Close() // TODO: How to handle errors from Close
		r.Logger.Debug("task completed")
	}()

	rfiles, _, err := r.RecvFileList()
	if err != nil {
		return nil, err
	}
	r.Logger.Debug("remote files count", slog.Int64("count", int64(len(rfiles))))

	if err := r.FinalPhase(); err != nil {
		return nil, err
	}
	return rfiles, nil
}
