package rsync

type Attribs struct {
	Sender     bool // --sender
	Server     bool // --server
	Recursive  bool // -r
	DryRun     bool // -n
	HasModTime bool // -t
	HasPerms   bool // -p
	HasLinks   bool // -l
	HasGID     bool // -g
	HasUID     bool // -u
	// compress 	bool // -z
}

func (a *Attribs) Marshal() []byte {
	//"--server\n--sender\n-l\n-p\n-r\n-t\n.\n"
	args := make([]byte, 0, 64)
	if a.Server {
		args = append(args, []byte("--server\n")...)
	}
	if a.Sender {
		args = append(args, []byte("--sender\n")...)
	}
	if a.Recursive {
		args = append(args, []byte("-r\n")...)
	}
	if a.HasModTime {
		args = append(args, []byte("-t\n")...)
	}
	if a.HasLinks {
		args = append(args, []byte("-l\n")...)
	}
	if a.HasPerms {
		args = append(args, []byte("-p\n")...)
	}
	if a.HasGID {
		args = append(args, []byte("-g\n")...)
	}
	if a.HasUID {
		args = append(args, []byte("-u\n")...)
	}
	return args
}
