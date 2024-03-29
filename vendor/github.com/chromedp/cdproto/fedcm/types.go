package fedcm

// Code generated by cdproto-gen. DO NOT EDIT.

import (
	"fmt"

	"github.com/mailru/easyjson"
	"github.com/mailru/easyjson/jlexer"
	"github.com/mailru/easyjson/jwriter"
)

// LoginState whether this is a sign-up or sign-in action for this account,
// i.e. whether this account has ever been used to sign in to this RP before.
//
// See: https://chromedevtools.github.io/devtools-protocol/tot/FedCm#type-LoginState
type LoginState string

// String returns the LoginState as string value.
func (t LoginState) String() string {
	return string(t)
}

// LoginState values.
const (
	LoginStateSignIn LoginState = "SignIn"
	LoginStateSignUp LoginState = "SignUp"
)

// MarshalEasyJSON satisfies easyjson.Marshaler.
func (t LoginState) MarshalEasyJSON(out *jwriter.Writer) {
	out.String(string(t))
}

// MarshalJSON satisfies json.Marshaler.
func (t LoginState) MarshalJSON() ([]byte, error) {
	return easyjson.Marshal(t)
}

// UnmarshalEasyJSON satisfies easyjson.Unmarshaler.
func (t *LoginState) UnmarshalEasyJSON(in *jlexer.Lexer) {
	v := in.String()
	switch LoginState(v) {
	case LoginStateSignIn:
		*t = LoginStateSignIn
	case LoginStateSignUp:
		*t = LoginStateSignUp

	default:
		in.AddError(fmt.Errorf("unknown LoginState value: %v", v))
	}
}

// UnmarshalJSON satisfies json.Unmarshaler.
func (t *LoginState) UnmarshalJSON(buf []byte) error {
	return easyjson.Unmarshal(buf, t)
}

// DialogType whether the dialog shown is an account chooser or an auto
// re-authentication dialog.
//
// See: https://chromedevtools.github.io/devtools-protocol/tot/FedCm#type-DialogType
type DialogType string

// String returns the DialogType as string value.
func (t DialogType) String() string {
	return string(t)
}

// DialogType values.
const (
	DialogTypeAccountChooser DialogType = "AccountChooser"
	DialogTypeAutoReauthn    DialogType = "AutoReauthn"
)

// MarshalEasyJSON satisfies easyjson.Marshaler.
func (t DialogType) MarshalEasyJSON(out *jwriter.Writer) {
	out.String(string(t))
}

// MarshalJSON satisfies json.Marshaler.
func (t DialogType) MarshalJSON() ([]byte, error) {
	return easyjson.Marshal(t)
}

// UnmarshalEasyJSON satisfies easyjson.Unmarshaler.
func (t *DialogType) UnmarshalEasyJSON(in *jlexer.Lexer) {
	v := in.String()
	switch DialogType(v) {
	case DialogTypeAccountChooser:
		*t = DialogTypeAccountChooser
	case DialogTypeAutoReauthn:
		*t = DialogTypeAutoReauthn

	default:
		in.AddError(fmt.Errorf("unknown DialogType value: %v", v))
	}
}

// UnmarshalJSON satisfies json.Unmarshaler.
func (t *DialogType) UnmarshalJSON(buf []byte) error {
	return easyjson.Unmarshal(buf, t)
}

// Account corresponds to IdentityRequestAccount.
//
// See: https://chromedevtools.github.io/devtools-protocol/tot/FedCm#type-Account
type Account struct {
	AccountID         string     `json:"accountId"`
	Email             string     `json:"email"`
	Name              string     `json:"name"`
	GivenName         string     `json:"givenName"`
	PictureURL        string     `json:"pictureUrl"`
	IdpConfigURL      string     `json:"idpConfigUrl"`
	IdpSigninURL      string     `json:"idpSigninUrl"`
	LoginState        LoginState `json:"loginState"`
	TermsOfServiceURL string     `json:"termsOfServiceUrl,omitempty"` // These two are only set if the loginState is signUp
	PrivacyPolicyURL  string     `json:"privacyPolicyUrl,omitempty"`
}
