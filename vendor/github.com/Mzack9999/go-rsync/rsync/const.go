package rsync

//nolint:revive,stylecheck
const (
	RSYNC_VERSION  = "@RSYNCD: 27.0\n"
	RSYNC_AUTHREQD = "@RSYNCD: AUTHREQD"
	RSYNCD_OK      = "@RSYNCD: OK"
	RSYNC_EXIT     = "@RSYNCD: EXIT"

	K = 1 << 10
	M = 1 << 20
	G = 1 << 30

	MAXPATHLEN    = 1024
	INDEX_END     = int32(-1)
	EXCLUSION_END = int32(0)
	END1          = '\n'
	END2          = '\x00'
	PHASE_END     = int32(-1)

	// ARGUMENTS
	ARG_SERVER       = "--server"
	ARG_SENDER       = "--sender"
	ARG_SYMLINK      = "-l"
	ARG_RECURSIVE    = "-r"
	ARG_PERMS        = "-p"
	SAMPLE_ARGS      = "--server\n--sender\n-l\n-p\n-r\n-t\n.\n"
	SAMPLE_LIST_ARGS = "--server\n--sender\n--list-only\n-l\n-p\n-r\n-t\n.\n"

	// For Multiplex(1 byte)
	MUX_BASE       = 7
	MSG_DATA       = 0
	MSG_ERROR_XFER = 1
	MSG_INFO       = 2
	MSG_ERROR      = 3
	MSG_WARNING    = 4
	MSG_IO_ERROR   = 22
	MSG_NOOP       = 42
	MSG_SUCCESS    = 100
	MSG_DELETED    = 101
	MSG_NO_SEND    = 102

	// For FILE LIST(1 byte)
	FLIST_END       = 0x00
	FLIST_TOP_LEVEL = 0x01 /* needed for remote --delete */
	FLIST_MODE_SAME = 0x02 /* mode is repeat */
	FLIST_RDEV_SAME = 0x04 /* rdev is repeat */
	FLIST_UID_SAME  = 0x08 /* uid is repeat */
	FLIST_GID_SAME  = 0x10 /* gid is repeat */
	FLIST_NAME_SAME = 0x20 /* name is repeat */
	FLIST_NAME_LONG = 0x40 /* name >255 bytes */
	FLIST_TIME_SAME = 0x80 /* time is repeat */

	// File type
	S_IFMT   = 0o170000 /* Type of file */
	S_IFREG  = 0o100000 /* Regular file.  */
	S_IFDIR  = 0o040000 /* Directory.  */
	S_IFLNK  = 0o120000 /* Symbolic link.  */
	S_IFCHR  = 0o020000 /* Character device.  */
	S_IFBLK  = 0o060000 /* Block device.  */
	S_IFIFO  = 0o010000 /* FIFO.  */
	S_IFSOCK = 0o140000 /* Socket.  */
)
