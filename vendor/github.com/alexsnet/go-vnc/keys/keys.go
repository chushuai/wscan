// Package keys provides constants for all the keyboard inputs.
package keys

import "fmt"

// Key represents a VNC key press.
type Key uint32

//go:generate stringer -type=Key

// Keys is a slice of Key values.
type Keys []Key

var keymap = map[rune]Key{
	'-': Minus,
	'0': Digit0,
	'1': Digit1,
	'2': Digit2,
	'3': Digit3,
	'4': Digit4,
	'5': Digit5,
	'6': Digit6,
	'7': Digit7,
	'8': Digit8,
	'9': Digit9,
}

// IntToKeys returns Keys that represent the key presses required to type an int.
func IntToKeys(v int) Keys {
	k := Keys{}
	for _, c := range fmt.Sprintf("%d", v) {
		k = append(k, keymap[c])
	}
	return k
}

// Latin 1 (byte 3 = 0)
// ISO/IEC 8859-1 = Unicode U+0020..U+00FF
const (
	Space   Key = iota + 0x0020
	Exclaim     // exclamation mark
	QuoteDbl
	NumberSign
	Dollar
	Percent
	Ampersand
	Apostrophe
	ParenLeft
	ParenRight
	Asterisk
	Plus
	Comma
	Minus
	Period
	Slash
	Digit0
	Digit1
	Digit2
	Digit3
	Digit4
	Digit5
	Digit6
	Digit7
	Digit8
	Digit9
	Colon
	Semicolon
	Less
	Equal
	Greater
	Question
	At
	A
	B
	C
	D
	E
	F
	G
	H
	I
	J
	K
	L
	M
	N
	O
	P
	Q
	R
	S
	T
	U
	V
	W
	X
	Y
	Z
	BracketLeft
	Backslash
	BracketRight
	AsciiCircum
	Underscore
	Grave
	SmallA
	SmallB
	SmallC
	SmallD
	SmallE
	SmallF
	SmallG
	SmallH
	SmallI
	SmallJ
	SmallK
	SmallL
	SmallM
	SmallN
	SmallO
	SmallP
	SmallQ
	SmallR
	SmallS
	SmallT
	SmallU
	SmallV
	SmallW
	SmallX
	SmallY
	SmallZ
	BraceLeft
	Bar
	BraceRight
	AsciiTilde
)
const (
	BackSpace Key = iota + 0xff08
	Tab
	Linefeed
	Clear
	_
	Return
)
const (
	Pause Key = iota + 0xff13
	ScrollLock
	SysReq
	Escape Key = 0xff1b
	Delete Key = 0xffff
)
const ( // Cursor control & motion.
	Home Key = iota + 0xff50
	Left
	Up
	Right
	Down
	PageUp
	PageDown
	End
	Begin
)
const ( // Misc functions.
	Select Key = 0xff60
	Print
	Execute
	Insert
	Undo
	Redo
	Menu
	Find
	Cancel
	Help
	Break
	ModeSwitch Key = 0xff7e
	NumLock    Key = 0xff7f
)
const ( // Keypad functions.
	KeypadSpace Key = 0xff80
	KeypadTab   Key = 0xff89
	KeypadEnter Key = 0xff8d
)
const ( // Keypad functions cont.
	KeypadF1 Key = iota + 0xff91
	KeypadF2
	KeypadF3
	KeypadF4
	KeypadHome
	KeypadLeft
	KeypadUp
	KeypadRight
	KeypadDown
	KeypadPrior
	KeypadPageUp
	KeypadNext
	KeypadPageDown
	KeypadEnd
	KeypadBegin
	KeypadInsert
	KeypadDelete
	KeypadMultiply
	KeypadAdd
	KeypadSeparator
	KeypadSubtract
	KeypadDecimal
	KeypadDivide
	Keypad0
	Keypad1
	Keypad2
	Keypad3
	Keypad4
	Keypad5
	Keypad6
	Keypad7
	Keypad8
	Keypad9
	KeypadEqual Key = 0xffbd
)
const (
	F1 Key = iota + 0xffbe
	F2
	F3
	F4
	F5
	F6
	F7
	F8
	F9
	F10
	F11
	F12
)
const (
	ShiftLeft Key = iota + 0xffe1
	ShiftRight
	ControlLeft
	ControlRight
	CapsLock
	ShiftLock
	MetaLeft
	MetaRight
	AltLeft
	AltRight
	SuperLeft
	SuperRight
	HyperLeft
	HyperRight
)
