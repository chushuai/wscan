package rsync

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"

	"github.com/projectdiscovery/fastdialer/fastdialer"
	"golang.org/x/crypto/md4" //nolint // md4 is used for rsync protocol
)

type ClientOption func(*clientOptions)

func WithClientAuth(username, password string) ClientOption {
	return func(c *clientOptions) {
		c.Auth = &ClientAuth{
			Username: username,
			Password: password,
		}
	}
}

func WithExclusionList(exclusionList ExclusionList) ClientOption {
	return func(c *clientOptions) {
		c.ExclusionList = exclusionList
	}
}

func WithLogger(logger *slog.Logger) ClientOption {
	return func(c *clientOptions) {
		c.Logger = logger
	}
}

func WithFastDialer(fastdialer *fastdialer.Dialer) ClientOption {
	return func(c *clientOptions) {
		c.FastDialer = fastdialer
	}
}

type ClientAuth struct {
	Username string
	Password string
}

type clientOptions struct {
	Auth          *ClientAuth
	ExclusionList ExclusionList
	Logger        *slog.Logger
	FastDialer    *fastdialer.Dialer
}

/* As a Client, we need to:
1. connect to server by socket or ssh
2. handshake: version, args, ioerror
	PS: client always sends exclusions/filter list
3. construct a Receiver or a Sender, then excute it.
*/

// TODO: passes more arguments: cmd
// Connect to rsync daemon
func SocketClient(storage FS, address string, module string, path string, opts ...ClientOption) (SendReceiver, error) {
	co := clientOptions{
		Auth:          nil,
		ExclusionList: make(ExclusionList, 0),
		Logger:        slog.Default(),
	}

	for _, opt := range opts {
		opt(&co)
	}

	if co.FastDialer == nil {
		return nil, errors.New("fastdialer instance not provided")
	}

	skt, err := co.FastDialer.Dial(context.Background(), "tcp", address)
	if err != nil {
		return nil, err
	}

	conn := &Conn{
		Writer:    skt,
		Reader:    skt,
		Bytespool: make([]byte, 8),
	}

	/* HandShake by socket */
	// send my version
	_, err = conn.Write([]byte(RSYNC_VERSION))
	if err != nil {
		return nil, err
	}

	// receive server's protocol version and seed
	versionStr, _ := readLine(conn)

	// recv(version)
	var remoteProtocol, remoteProtocolSub int
	_, err = fmt.Sscanf(versionStr, "@RSYNCD: %d.%d\n", &remoteProtocol, &remoteProtocolSub)
	if err != nil {
		co.Logger.Error("failed to parse version", slog.String("error", err.Error()))
	}
	co.Logger.Debug("remote protocol", slog.Int("protocol", remoteProtocol), slog.Int("sub", remoteProtocolSub))

	buf := new(bytes.Buffer)

	// send mod name
	buf.WriteString(module)
	buf.WriteByte('\n')
	_, err = conn.Write(buf.Bytes())
	if err != nil {
		return nil, err
	}
	buf.Reset()

	// Wait for '@RSYNCD: OK'
	for {
		res, err := readLine(conn)
		if err != nil {
			return nil, err
		}

		if strings.Contains(res, RSYNCD_OK) {
			co.Logger.Debug("OK received")
			break
		}

		// Check for auth request
		if strings.Contains(res, RSYNC_AUTHREQD) {
			if co.Auth == nil {
				return nil, fmt.Errorf("server requires auth")
			}

			// Parse challenge from server
			var challenge string
			_, err = fmt.Sscanf(res, "@RSYNCD: AUTHREQD %s", &challenge)
			if err != nil {
				return nil, fmt.Errorf("failed to parse challenge")
			}

			// Calculate challenge response with md4 of password + challenge
			h := md4.New()
			h.Write([]byte("\x00\x00\x00\x00"))
			_, err := io.WriteString(h, co.Auth.Password)
			if err != nil {
				return nil, err
			}

			_, err = io.WriteString(h, challenge)
			if err != nil {
				return nil, err
			}

			buf.WriteString(fmt.Sprintf("%s %s\n", co.Auth.Username, base64.RawStdEncoding.EncodeToString(h.Sum(nil))))

			_, err = conn.Write(buf.Bytes())
			if err != nil {
				return nil, err
			}
			buf.Reset()
		}
	}

	// Send arguments
	buf.WriteString(SAMPLE_ARGS)
	buf.WriteString(module)
	buf.WriteString(path)
	buf.WriteString("\n\n")
	_, err = conn.Write(buf.Bytes())
	if err != nil {
		return nil, err
	}
	buf.Reset()

	// read int32 as seed
	seed, err := conn.ReadInt()
	if err != nil {
		return nil, err
	}
	co.Logger.Debug("seed received", slog.Any("seed", seed))

	// HandShake OK
	co.Logger.Debug("handshake completed")

	// Begin to demux
	conn.Reader = NewMuxReader(conn.Reader, co.Logger)

	// Send exclusion list
	err = co.ExclusionList.SendExlusionList(conn)
	if err != nil {
		return nil, err
	}

	// TODO: Sender

	return &Receiver{
		Conn:    conn,
		Module:  module,
		Path:    path,
		Seed:    seed,
		Storage: storage,
		Logger:  co.Logger,
	}, nil
}

// Connect to sshd, and start a rsync server on remote
func SSHClient(storage FS, address string, module string, path string, _ map[string]string) (SendReceiver, error) {
	// TODO: build args

	ssh, err := NewSSH(address, "", "", "rsync --server --sender -l -p -r -t")
	if err != nil {
		return nil, err
	}
	conn := &Conn{
		Writer:    ssh,
		Reader:    ssh,
		Bytespool: make([]byte, 8),
	}

	// Handshake
	lver, err := conn.ReadInt()
	if err != nil {
		return nil, err
	}

	rver, err := conn.ReadInt()
	if err != nil {
		return nil, err
	}

	seed, err := conn.ReadInt()
	if err != nil {
		return nil, err
	}

	// TODO: Sender

	return &Receiver{
		Conn:    conn,
		Module:  module,
		Path:    path,
		Seed:    seed,
		LVer:    lver,
		RVer:    rver,
		Storage: storage,
	}, nil
}

// ListModules connects to an rsync server and returns a list of available modules
func ListModules(address string, opts ...ClientOption) ([]ModuleInfo, error) {
	co := clientOptions{
		Auth:          nil, // No auth needed for module listing
		ExclusionList: make(ExclusionList, 0),
		Logger:        slog.Default(),
	}

	for _, opt := range opts {
		opt(&co)
	}

	if co.FastDialer == nil {
		return nil, errors.New("fastdialer instance not provided")
	}

	// Establish TCP connection
	skt, err := co.FastDialer.Dial(context.Background(), "tcp", address)
	if err != nil {
		return nil, fmt.Errorf("failed to connect: %w", err)
	}
	defer skt.Close()

	// Set connection timeout
	if err := skt.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		return nil, fmt.Errorf("failed to set connection timeout: %w", err)
	}

	conn := &Conn{
		Writer:    skt,
		Reader:    skt,
		Bytespool: make([]byte, 8),
	}

	// Simple handshake: send version, then send empty line to trigger module list
	_, err = conn.Write([]byte("@RSYNCD: 27.0\n\n"))
	if err != nil {
		return nil, fmt.Errorf("failed to send version and empty line: %w", err)
	}

	// Read server version response
	versionStr, err := readLine(conn)
	if err != nil {
		return nil, fmt.Errorf("failed to read server version: %w", err)
	}
	co.Logger.Debug("server version", slog.String("version", versionStr))

	// Server now sends module list after receiving empty line
	co.Logger.Debug("reading module list from server")

	// Reset timeout for reading module list
	if err := skt.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
		return nil, fmt.Errorf("failed to reset timeout: %w", err)
	}

	// Read module list
	var modules []ModuleInfo
	maxLines := 1000 // Prevent infinite loops
	lineCount := 0

	for lineCount < maxLines {
		co.Logger.Debug("attempting to read line", slog.Int("line_number", lineCount+1))

		// Set a very short timeout for each readLine call
		if err := skt.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
			return nil, fmt.Errorf("failed to set read timeout: %w", err)
		}

		line, err := readLine(conn)
		if err != nil {
			if err == io.EOF {
				co.Logger.Debug("connection closed by server")
				break
			}
			co.Logger.Debug("error reading line", slog.String("error", err.Error()))
			break
		}

		lineCount++
		co.Logger.Debug("read line", slog.String("line", line), slog.Int("count", lineCount), slog.String("hex", fmt.Sprintf("%x", []byte(line))))

		// Skip empty lines
		if strings.TrimSpace(line) == "" {
			continue
		}

		// Check for exit
		if strings.Contains(line, "@RSYNCD: EXIT") {
			co.Logger.Debug("EXIT received")
			break
		}

		// Skip RSYNCD lines
		if strings.HasPrefix(line, "@RSYNCD:") {
			co.Logger.Debug("skipping RSYNCD line", slog.String("line", line))
			continue
		}

		// Parse module line: "module_name\tcomment" or "module_name comment"
		parts := strings.SplitN(line, "\t", 2)
		if len(parts) == 1 {
			// Try space-separated format
			parts = strings.SplitN(line, " ", 2)
		}

		if len(parts) >= 1 && strings.TrimSpace(parts[0]) != "" {
			moduleInfo := ModuleInfo{
				Name: strings.TrimSpace(parts[0]),
			}
			if len(parts) > 1 {
				moduleInfo.Comment = strings.TrimSpace(parts[1])
			}
			modules = append(modules, moduleInfo)
			co.Logger.Debug("parsed module", slog.String("name", moduleInfo.Name), slog.String("comment", moduleInfo.Comment))
		} else {
			co.Logger.Debug("skipping unparseable line", slog.String("line", line))
		}
	}

	if lineCount >= maxLines {
		co.Logger.Warn("reached maximum line count, server may be misbehaving")
	}

	co.Logger.Debug("module listing completed", slog.Int("total_modules", len(modules)))
	return modules, nil
}

// ListModuleFiles lists files in a specific module using the proper rsync protocol
func ListModuleFiles(address string, module string, path string, opts ...ClientOption) ([]string, error) {
	co := clientOptions{
		Auth:          nil, // Will be set by options
		ExclusionList: make(ExclusionList, 0),
		Logger:        slog.Default(),
	}

	for _, opt := range opts {
		opt(&co)
	}

	if co.FastDialer == nil {
		return nil, errors.New("fastdialer instance not provided")
	}

	// Check if we have authentication
	if co.Auth == nil {
		return nil, fmt.Errorf("authentication required for file listing")
	}

	// Establish TCP connection
	skt, err := co.FastDialer.Dial(context.Background(), "tcp", address)
	if err != nil {
		return nil, fmt.Errorf("failed to connect: %w", err)
	}
	defer skt.Close()

	// Set connection timeout
	if err := skt.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		return nil, fmt.Errorf("failed to set connection timeout: %w", err)
	}

	conn := &Conn{
		Writer:    skt,
		Reader:    skt,
		Bytespool: make([]byte, 8),
	}

	// Perform handshake for file listing
	if err := performFileListHandshake(conn, co, module); err != nil {
		return nil, fmt.Errorf("handshake failed: %w", err)
	}

	// Send file listing arguments using SAMPLE_LIST_ARGS
	buf := new(bytes.Buffer)
	buf.WriteString(SAMPLE_LIST_ARGS)
	buf.WriteString(module)
	buf.WriteString(path)
	buf.WriteString("\n\n")

	if _, err := conn.Write(buf.Bytes()); err != nil {
		return nil, fmt.Errorf("failed to send arguments: %w", err)
	}

	// Read seed
	seed, err := conn.ReadInt()
	if err != nil {
		return nil, fmt.Errorf("failed to read seed: %w", err)
	}
	co.Logger.Debug("seed received", slog.Any("seed", seed))

	// Begin to demux
	conn.Reader = NewMuxReader(conn.Reader, co.Logger)

	// Send exclusion list
	err = co.ExclusionList.SendExlusionList(conn)
	if err != nil {
		return nil, fmt.Errorf("failed to send exclusion list: %w", err)
	}

	// Now read the file list
	files, err := readFileListFromConn(conn, co.Logger)
	if err != nil {
		return nil, fmt.Errorf("failed to read file list: %w", err)
	}

	return files, nil
}

// performSimpleModuleListHandshake performs a simple rsync daemon handshake for module listing (no auth)
func performSimpleModuleListHandshake(conn *Conn, co clientOptions) error {
	// Send rsync version
	_, err := conn.Write([]byte(RSYNC_VERSION))
	if err != nil {
		return fmt.Errorf("failed to send version: %w", err)
	}

	// Receive server's protocol version
	versionStr, err := readLine(conn)
	if err != nil {
		return fmt.Errorf("failed to read server version: %w", err)
	}

	// Parse version (optional, just for logging)
	var remoteProtocol, remoteProtocolSub int
	if _, err := fmt.Sscanf(versionStr, "@RSYNCD: %d.%d", &remoteProtocol, &remoteProtocolSub); err == nil {
		co.Logger.Debug("remote protocol", slog.Int("protocol", remoteProtocol), slog.Int("sub", remoteProtocolSub))
	} else {
		co.Logger.Debug("unable to parse server version", slog.String("version", versionStr))
	}

	// Wait for '@RSYNCD: OK' - module listing doesn't require auth
	for {
		res, err := readLine(conn)
		if err != nil {
			return fmt.Errorf("failed to read response: %w", err)
		}

		co.Logger.Debug("handshake response", slog.String("response", res))

		if strings.Contains(res, RSYNCD_OK) {
			co.Logger.Debug("OK received")
			break
		}

		// If server asks for auth, module listing is not supported
		if strings.Contains(res, RSYNC_AUTHREQD) {
			return fmt.Errorf("server requires authentication for module listing, this is unusual")
		}

		// Check for other rsync protocol responses
		if strings.Contains(res, "@RSYNCD: EXIT") {
			return fmt.Errorf("server terminated connection during handshake")
		}
	}

	co.Logger.Debug("handshake completed successfully")
	return nil
}

// performFileListHandshake performs the rsync daemon handshake for file listing
func performFileListHandshake(conn *Conn, co clientOptions, module string) error {
	// Send rsync version
	_, err := conn.Write([]byte(RSYNC_VERSION))
	if err != nil {
		return fmt.Errorf("failed to send version: %w", err)
	}

	// Receive server's protocol version
	versionStr, err := readLine(conn)
	if err != nil {
		return fmt.Errorf("failed to read server version: %w", err)
	}

	// Parse version (optional, just for logging)
	var remoteProtocol, remoteProtocolSub int
	if _, err := fmt.Sscanf(versionStr, "@RSYNCD: %d.%d", &remoteProtocol, &remoteProtocolSub); err == nil {
		co.Logger.Debug("remote protocol", slog.Int("protocol", remoteProtocol), slog.Int("sub", remoteProtocolSub))
	} else {
		co.Logger.Debug("unable to parse server version", slog.String("version", versionStr))
	}

	// Wait for '@RSYNCD: OK' or handle authentication
	maxAuthAttempts := 5
	authAttempts := 0

	for authAttempts < maxAuthAttempts {
		res, err := readLine(conn)
		if err != nil {
			return fmt.Errorf("failed to read response: %w", err)
		}

		co.Logger.Debug("handshake response", slog.String("response", res))

		if strings.Contains(res, RSYNCD_OK) {
			co.Logger.Debug("OK received")
			break
		}

		// Check for auth request
		if strings.Contains(res, RSYNC_AUTHREQD) {
			if co.Auth == nil {
				return fmt.Errorf("server requires auth but no credentials provided")
			}

			// Parse challenge from server
			var challenge string
			if _, err := fmt.Sscanf(res, "@RSYNCD: AUTHREQD %s", &challenge); err != nil {
				return fmt.Errorf("failed to parse challenge: %w", err)
			}

			co.Logger.Debug("auth required", slog.String("challenge", challenge))

			// Calculate challenge response with md4 of password + challenge
			h := md4.New()
			h.Write([]byte("\x00\x00\x00\x00"))
			if _, err := io.WriteString(h, co.Auth.Password); err != nil {
				return fmt.Errorf("failed to write password to hash: %w", err)
			}
			if _, err := io.WriteString(h, challenge); err != nil {
				return fmt.Errorf("failed to write challenge to hash: %w", err)
			}

			authResponse := fmt.Sprintf("%s %s\n", co.Auth.Username, base64.RawStdEncoding.EncodeToString(h.Sum(nil)))
			if _, err := conn.Write([]byte(authResponse)); err != nil {
				return fmt.Errorf("failed to send auth response: %w", err)
			}

			authAttempts++
			co.Logger.Debug("auth response sent", slog.Int("attempt", authAttempts))
		}

		// Check for other rsync protocol responses
		if strings.Contains(res, "@RSYNCD: EXIT") {
			return fmt.Errorf("server terminated connection during handshake")
		}

		// Prevent infinite loop
		if authAttempts >= maxAuthAttempts {
			return fmt.Errorf("too many authentication attempts, possible protocol error")
		}
	}

	// Send module name
	if _, err := conn.Write([]byte(module + "\n")); err != nil {
		return fmt.Errorf("failed to send module name: %w", err)
	}

	// Wait for '@RSYNCD: OK' again
	for {
		res, err := readLine(conn)
		if err != nil {
			return fmt.Errorf("failed to read module response: %w", err)
		}

		if strings.Contains(res, RSYNCD_OK) {
			co.Logger.Debug("module OK received")
			break
		}

		if strings.Contains(res, "@RSYNCD: EXIT") {
			return fmt.Errorf("server terminated connection after module selection")
		}
	}

	co.Logger.Debug("handshake completed successfully")
	return nil
}

// readFileListFromConn reads the file list from the rsync connection
func readFileListFromConn(conn *Conn, logger *slog.Logger) ([]string, error) {
	var files []string
	maxFiles := 100000 // Prevent infinite loops
	fileCount := 0

	for fileCount < maxFiles {
		// Read flags byte
		flagsBuf := make([]byte, 1)
		_, err := conn.Read(flagsBuf)
		if err != nil {
			if err == io.EOF {
				logger.Debug("connection closed by server")
				break
			}
			return nil, fmt.Errorf("failed to read flags: %w", err)
		}

		flags := flagsBuf[0]
		logger.Debug("read flags", slog.Int("flags", int(flags)), slog.Int("file_count", fileCount))

		// Check for end of file list
		if flags == 0x00 { // FLIST_END
			logger.Debug("end of file list")
			break
		}

		// Read filename
		filename, err := readFilenameFromConn(conn, flags)
		if err != nil {
			return nil, fmt.Errorf("failed to read filename: %w", err)
		}

		// Skip other file metadata for now (we only need filenames)
		if err := skipFileMetadataFromConn(conn, flags); err != nil {
			return nil, fmt.Errorf("failed to skip file metadata: %w", err)
		}

		files = append(files, filename)
		fileCount++
		logger.Debug("added file", slog.String("filename", filename), slog.Int("total", fileCount))
	}

	if fileCount >= maxFiles {
		logger.Warn("reached maximum file count, server may be misbehaving")
	}

	return files, nil
}

// readFilenameFromConn reads the filename based on the flags
func readFilenameFromConn(conn *Conn, flags byte) (string, error) {
	var pathlen uint32

	// Handle FLIST_NAME_SAME flag (skip partial length for now)
	if (flags & 0x20) != 0 { // FLIST_NAME_SAME
		partialBuf := make([]byte, 1)
		_, err := conn.Read(partialBuf)
		if err != nil {
			return "", fmt.Errorf("failed to read partial length: %w", err)
		}
		// partial := uint32(partialBuf[0]) // Not used in this simplified version
	}

	// Handle FLIST_NAME_LONG flag
	if (flags & 0x40) != 0 { // FLIST_NAME_LONG
		pathlenBuf := make([]byte, 4)
		_, err := conn.Read(pathlenBuf)
		if err != nil {
			return "", fmt.Errorf("failed to read path length: %w", err)
		}
		pathlen = uint32(binary.LittleEndian.Uint32(pathlenBuf))
	} else {
		pathlenBuf := make([]byte, 1)
		_, err := conn.Read(pathlenBuf)
		if err != nil {
			return "", fmt.Errorf("failed to read path length: %w", err)
		}
		pathlen = uint32(pathlenBuf[0])
	}

	// Read the filename bytes
	filenameBytes := make([]byte, pathlen)
	_, err := conn.Read(filenameBytes)
	if err != nil {
		return "", fmt.Errorf("failed to read filename bytes: %w", err)
	}

	return string(filenameBytes), nil
}

// skipFileMetadataFromConn skips over file metadata we don't need
func skipFileMetadataFromConn(conn *Conn, flags byte) error {
	// Skip size (always present)
	sizeBuf := make([]byte, 8)
	if _, err := conn.Read(sizeBuf); err != nil {
		return fmt.Errorf("failed to skip size: %w", err)
	}

	// Skip mtime if not FLIST_TIME_SAME
	if (flags & 0x80) == 0 { // FLIST_TIME_SAME
		mtimeBuf := make([]byte, 4)
		if _, err := conn.Read(mtimeBuf); err != nil {
			return fmt.Errorf("failed to skip mtime: %w", err)
		}
	}

	// Skip mode if not FLIST_MODE_SAME
	if (flags & 0x02) == 0 { // FLIST_MODE_SAME
		modeBuf := make([]byte, 4)
		if _, err := conn.Read(modeBuf); err != nil {
			return fmt.Errorf("failed to skip mode: %w", err)
		}
	}

	return nil
}

// ModuleInfo contains information about an rsync module
type ModuleInfo struct {
	Name    string
	Comment string
}
