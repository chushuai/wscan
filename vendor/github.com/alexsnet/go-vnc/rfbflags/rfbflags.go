/*
Package rfbflags provides constants for the RFB flag values.
*/
package rfbflags

// RFBFlag represents a RFB Flag value.
type RFBFlag uint8

//go:generate stringer -type=RFBFlag

// RFB flag values.
const (
	RFBFalse RFBFlag = iota
	RFBTrue
)

func BoolToRFBFlag(b bool) RFBFlag {
	if b == true {
		return RFBTrue
	}
	return RFBFalse
}

// To returns true if the flag value != RFBFalse.
func ToBool(f RFBFlag) bool {
	// Using != as any non-zero RFBFlag value equates to true.
	return f != RFBFalse
}

// IsBigEndian returns true if the flag value != RFBFalse.
func IsBigEndian(f RFBFlag) bool {
	return ToBool(f)
}

// IsTrueColor returns true if the flag value != RFBFalse.
func IsTrueColor(f RFBFlag) bool {
	return ToBool(f)
}
