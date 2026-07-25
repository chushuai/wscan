/*
Package encodings provides constants for the known VNC encoding types.
https://tools.ietf.org/html/rfc6143#section-7.7
*/
package encodings

// Encoding represents a known VNC encoding type.
type Encoding int32

//go:generate stringer -type=Encoding

const (
	Raw               Encoding = 0
	CopyRect          Encoding = 1
	RRE               Encoding = 2
	Hextile           Encoding = 5
	TRLE              Encoding = 15
	ZRLE              Encoding = 16
	ColorPseudo       Encoding = -239
	DesktopSizePseudo Encoding = -223
)
