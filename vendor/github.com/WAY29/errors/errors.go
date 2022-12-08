package errors

import (
	"fmt"
	"io"
)

type Error struct {
	msg           string
	errorType     interface{}
	originalError error
	*stack
}

type causer interface {
	Cause() error
}

func New(msg string) error {
	return Error{msg: msg, errorType: "", originalError: nil, stack: callers()}
}

func Newf(format string, args ...interface{}) error {
	msg := fmt.Sprintf(format, args...)
	return Error{msg: msg, errorType: "", originalError: nil, stack: callers()}
}

func Errorf(format string, args ...interface{}) error {
	return Error{
		msg:           fmt.Sprintf(format, args...),
		errorType:     "",
		originalError: nil,
		stack:         callers(),
	}
}

func Wrap(err error, msg string) error {
	if err == nil {
		return nil
	}
	if msg != "" {
		msg += ": "
	}
	if customErr, ok := err.(Error); ok {
		customErr.stack = nil
		return Error{
			msg: fmt.Sprintf("%s%s", msg, customErr.msg), errorType: customErr.errorType,
			originalError: customErr,
			stack:         callers(),
		}
	}

	return Error{msg: fmt.Sprintf("%s%s", msg, err.Error()), errorType: "", originalError: err, stack: callers()}
}

func Wrapf(err error, format string, args ...interface{}) error {
	if err == nil {
		return nil
	}
	msg := fmt.Sprintf(format, args...)
	if msg != "" {
		msg += ": "
	}

	if customErr, ok := err.(Error); ok {
		customErr.stack = nil
		return Error{
			msg:           fmt.Sprintf("%s%s", msg, customErr.msg),
			errorType:     customErr.errorType,
			originalError: customErr,
			stack:         callers(),
		}
	}

	return Error{msg: fmt.Sprintf("%s%s", msg, err.Error()), errorType: "", originalError: err, stack: callers()}
}

func GetType(err error) interface{} {
	if customErr, ok := err.(Error); ok {
		return customErr.errorType
	}
	return ""
}

func SetType(err error, errorType interface{}) (error, bool) {
	if customErr, ok := err.(Error); ok {
		customErr.errorType = errorType
		return customErr, true
	}
	return err, false
}

func SetTypeWithoutBool(err error, errorType interface{}) error {
	err, _ = SetType(err, errorType)
	return err
}

func Cause(err error) error {
	var oldErr error
	for err != nil {
		oldErr = err
		cause, ok := err.(causer)
		if !ok {
			break
		}
		err = cause.Cause()
		if err == nil {
			err = error(oldErr)
			break
		}
	}
	return err
}

func (err Error) Cause() error {
	return err.originalError
}

func (err Error) Error() string {
	return err.msg
}

func (err Error) Unwrap() error {
	return err.originalError
}

func (err Error) Format(s fmt.State, verb rune) {
	switch verb {
	case 'v':
		if s.Flag('+') {
			io.WriteString(s, err.Error())
			fmt.Fprintf(s, "%+v", err.stack)
		} else if s.Flag('#') {
			fmt.Fprintf(s, "%+v", err.stack)
		} else {
			io.WriteString(s, err.Error())
		}
	case 's':
		io.WriteString(s, err.Error())
	case 'q':
		fmt.Fprintf(s, "%q", err.Error())
	}
}
