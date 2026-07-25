package gozero

import "errors"

var (
	// ErrNoValidEngine is returned when no valid engine is found
	ErrNoValidEngine = errors.New("no valid engine found")

	// ErrNoEngines is returned when no engines are provided
	ErrNoEngines = errors.New("no engines provided")
)
