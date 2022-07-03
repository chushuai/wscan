package errors

import (
	"fmt"

	"github.com/WAY29/errors"
)

type ErrorType uint16

const (
	Unknown ErrorType = iota
	ConvertInterfaceError
	EnvInitializationError
	CompileError
	ProgramCreationError
	EvaluationError
	ProxyError
	RequestError
	ResponseError
	FileError
	FileNotFoundError
)

type CustomError struct {
	Type ErrorType
	Msg  string
}

func (err CustomError) Error() string {
	return err.Msg
}

func New(Type ErrorType, msg string) error {
	return errors.Wrap(CustomError{Type: Type, Msg: msg}, "")
}

func Newf(Type ErrorType, format string, args ...interface{}) error {
	return errors.Wrap(CustomError{Type: Type, Msg: fmt.Sprintf(format, args...)}, "")
}

func Wrap(err error, msg string) error {
	return errors.Wrap(err, msg)
}

func Wrapf(err error, format string, args ...interface{}) error {
	return errors.Wrapf(err, format, args...)
}
