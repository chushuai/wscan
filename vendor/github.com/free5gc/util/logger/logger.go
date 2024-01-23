package logger

import (
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httputil"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	formatter "github.com/tim-ywliu/nested-logrus-formatter"
)

const (
	RFC3339Nano = "2006-01-02T15:04:05.000000000Z07:00"
)

const (
	FieldNF                 string = "NF"
	FieldCategory           string = "CAT"
	FieldListenAddr         string = "LAddr"
	FieldRemoteAddr         string = "RAddr"
	FieldRanAddr            string = "RanAddr"
	FieldRanID              string = "RanID"
	FieldRanType            string = "RanTP"
	FieldRanUeNgapID        string = "RUID"
	FieldAmfUeNgapID        string = "AUID"
	FieldSuci               string = "SUCI"
	FieldSupi               string = "SUPI"
	FieldPDUSessionID       string = "PDUID"
	FieldControlPlaneNodeID string = "CPNodeID"
	FieldUserPlaneNodeID    string = "UPNodeID"
	FieldPFCPTxTransaction  string = "TXTR"
	FieldPFCPRxTransaction  string = "RXTR"
	FieldControlPlaneSEID   string = "CPSEID"
	FieldUserPlaneSEID      string = "UPSEID"
	FieldApplicationID      string = "APPID"
)

type FileHook struct {
	file      *os.File
	flag      int
	chmod     os.FileMode
	formatter *logrus.TextFormatter
}

// Fire(*Entry) implementation for logrus Hook interface
func (h *FileHook) Fire(entry *logrus.Entry) error {
	plainformat, err := h.formatter.Format(entry)
	if err != nil {
		return fmt.Errorf("FileHook formatter error: %+v\n", err)
	}

	line := string(plainformat)
	_, err = h.file.WriteString(line)
	if err != nil {
		return fmt.Errorf("unable to write file on filehook(%s): %+v\n", line, err)
	}

	return nil
}

// Levels() implementation for logrus Hook interface
func (h *FileHook) Levels() []logrus.Level {
	return []logrus.Level{
		logrus.PanicLevel,
		logrus.FatalLevel,
		logrus.ErrorLevel,
		logrus.WarnLevel,
		logrus.InfoLevel,
		logrus.DebugLevel,
		logrus.TraceLevel,
	}
}

func NewFileHook(file string, flag int, chmod os.FileMode) (*FileHook, error) {
	plainFormatter := &logrus.TextFormatter{
		DisableColors:   true,
		ForceQuote:      true,
		TimestampFormat: RFC3339Nano,
	}
	logFile, err := os.OpenFile(file, flag, chmod)
	if err != nil {
		return nil, fmt.Errorf("unable to open file(%s): %+v\n", file, err)
	}

	return &FileHook{logFile, flag, chmod, plainFormatter}, nil
}

func New(fieldsOrder []string) *logrus.Logger {
	log := logrus.New()
	log.SetReportCaller(false)

	log.Formatter = &formatter.Formatter{
		FieldsOrder:     fieldsOrder,
		TimestampFormat: RFC3339Nano,
		TrimMessages:    true,
		NoFieldsSpace:   true,
		HideKeys:        false,
		HidePartialKeys: map[string]bool{
			FieldNF:       true,
			FieldCategory: true,
			FieldRanID:    true,
			FieldRanType:  true,
			FieldSuci:     true,
			FieldSupi:     true,
		},
		CustomCallerFormatter: func(f *runtime.Frame) string {
			s := strings.Split(f.Function, ".")
			funcName := s[len(s)-1]
			return fmt.Sprintf(" [%s:%d][%s()]", path.Base(f.File), f.Line, funcName)
		},
	}
	return log
}

func LogFileHook(log *logrus.Logger, logPath string) error {
	if log == nil {
		return errors.New("LogFileHook err: nil logger")
	}

	filePath, err := createLogFile(logPath, false)
	if err != nil {
		return errors.Wrap(err, "LogFileHook err")
	}

	fhook, err := NewFileHook(
		filePath, os.O_CREATE|os.O_APPEND|os.O_RDWR, 0o666)
	if err != nil {
		return errors.Wrap(err, "LogFileHook err")
	}
	log.AddHook(fhook)

	return nil
}

/*
 * createLogFile
 * @param file, The full file path from arguments input by user.
 * @param rename, Modify the file name if the file exists
 * @return filePath, error
 */
func createLogFile(file string, rename bool) (string, error) {
	dir, fileName := filepath.Split(file)
	if fileName == "" {
		return "", errors.New("no file path")
	}
	if dir == "" {
		dir = "./log/"
		file = filepath.Join(dir, fileName)
	}

	if rename {
		if err := renameOldLogFile(file); err != nil {
			return "", err
		}
	}

	if err := os.MkdirAll(dir, 0o775); err != nil {
		return "", errors.Errorf("Make dir(%s) failed: %+v\n", dir, err)
	}

	sudoUID, errUID := strconv.Atoi(os.Getenv("SUDO_UID"))
	sudoGID, errGID := strconv.Atoi(os.Getenv("SUDO_GID"))
	if errUID == nil && errGID == nil {
		// if using sudo to run the program, errUID will be nil and sudoUID will get the uid who run sudo
		// else errUID will not be nil and sudoUID will be nil
		// If user using sudo to run the program and create log file, log will own by root,
		// here we change own to user so user can view and reuse the file
		err := os.Chown(dir, sudoUID, sudoGID)
		if err != nil {
			return "", errors.Errorf("Dir(%s) chown to [%d:%d] error: %+v\n", dir, sudoUID, sudoGID, err)
		}

		// Create log file or if it already exist, check if user can access it
		f, err := os.OpenFile(file, os.O_CREATE|os.O_APPEND|os.O_RDWR, 0o666)
		if err != nil {
			// user cannot access it.
			return "", errors.Errorf("Cannot Open [%s] error: %+v\n", file, err)
		}

		// user can access it
		err = f.Close()
		if err != nil {
			return "", errors.Errorf("File [%s] cannot been closed\n", file)
		}
		err = os.Chown(file, sudoUID, sudoGID)
		if err != nil {
			return "", errors.Errorf("File [%s] chown to [%d:%d] error: %+v\n", file, sudoUID, sudoGID, err)
		}
	}

	return file, nil
}

func renameOldLogFile(file string) error {
	_, err := os.Stat(file)

	if os.IsNotExist(err) {
		return nil
	}

	counter := 0
	sep := "."
	fileDir, fileName := filepath.Split(file)

	contents, err := ioutil.ReadDir(fileDir)
	if err != nil {
		return errors.Errorf("Reads the directory(%s) error %+v\n", fileDir, err)
	}
	for _, content := range contents {
		if !content.IsDir() {
			if strings.Contains(content.Name(), (fileName + sep)) {
				counter++
			}
		}
	}

	newFile := fmt.Sprintf("%s%s%s%d", fileDir, fileName, sep, (counter + 1))
	err = os.Rename(file, newFile)
	if err != nil {
		return errors.Errorf("Unable to rename file(%s) %+v\n", newFile, err)
	}

	return nil
}

// NewGinWithLogrus - returns an Engine instance with the ginToLogrus and Recovery middleware already attached.
func NewGinWithLogrus(log *logrus.Entry) *gin.Engine {
	engine := gin.New()
	engine.Use(ginToLogrus(log), ginRecover(log))
	return engine
}

// The Middleware will write the Gin logs to logrus.
func ginToLogrus(log *logrus.Entry) gin.HandlerFunc {
	return func(c *gin.Context) {
		path := c.Request.URL.Path
		raw := c.Request.URL.RawQuery

		// Process request
		c.Next()

		clientIP := c.ClientIP()
		method := c.Request.Method
		statusCode := c.Writer.Status()
		errorMessage := c.Errors.ByType(gin.ErrorTypePrivate).String()

		if raw != "" {
			path = path + "?" + raw
		}

		log.Infof("| %3d | %15s | %-7s | %s | %s",
			statusCode, clientIP, method, path, errorMessage)
	}
}

// The Middleware will recover the Gin panic to logrus.
func ginRecover(log *logrus.Entry) gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			if p := recover(); p != nil {
				// Check for a broken connection, as it is not really a condition that warrants a panic stack trace.
				var brokenPipe bool
				if ne, ok := p.(*net.OpError); ok {
					if se, ok := ne.Err.(*os.SyscallError); ok {
						if strings.Contains(strings.ToLower(se.Error()), "broken pipe") ||
							strings.Contains(strings.ToLower(se.Error()), "connection reset by peer") {
							brokenPipe = true
						}
					}
				}

				if log != nil {
					stack := string(debug.Stack())
					if httpRequest, err := httputil.DumpRequest(c.Request, false); err != nil {
						log.Errorf("Dump http request error: %v\n", err)
					} else {
						headers := strings.Split(string(httpRequest), "\r\n")
						for idx, header := range headers {
							current := strings.Split(header, ":")
							if current[0] == "Authorization" {
								headers[idx] = current[0] + ": *"
							}
						}

						// changing Fatalf to Errorf to let program not be exited
						if brokenPipe {
							log.Errorf("%v\n%s", p, string(httpRequest))
						} else if gin.IsDebugging() {
							log.Errorf("[Debugging] panic:\n%s\n%v\n%s", strings.Join(headers, "\r\n"), p, stack)
						} else {
							log.Errorf("panic: %v\n%s", p, stack)
						}
					}
				}

				// If the connection is dead, we can't write a status to it.
				if brokenPipe {
					c.Error(p.(error)) // nolint: errcheck
					c.Abort()
				} else {
					c.AbortWithStatus(http.StatusInternalServerError)
				}
			}
		}()
		c.Next()
	}
}
