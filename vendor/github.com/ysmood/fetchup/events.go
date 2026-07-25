package fetchup

type Event string

const (
	EventDownload   Event = "Download:"
	EventProgress   Event = "Progress:"
	EventUnzip      Event = "Unzip:"
	EventDownloaded Event = "Downloaded:"
)
