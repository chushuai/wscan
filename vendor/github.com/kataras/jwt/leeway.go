package jwt

import (
	"errors"
	"time"
)

// Leeway adds validation for a leeway expiration time.
// If the token was not expired then a comparison between
// this "leeway" and the token's "exp" one is expected to pass instead (now+leeway > exp).
// Example of use case: disallow tokens that are going to be expired in 3 seconds from now,
// this is useful to make sure that the token is valid when the when the user fires a database call for example.
func Leeway(leeway time.Duration) TokenValidatorFunc {
	return func(_ []byte, standardClaims Claims, err error) error {
		if err == nil {
			if Clock().Add(leeway).Round(time.Second).Unix() > standardClaims.Expiry {
				return ErrExpired
			}
		}

		return err
	}
}

// Future adds a validation for the "iat" claim.
// It checks if the token was issued in the future based on now+dur < iat.
//
// Example of use case: allow tokens that are going to be issued in the future,
// for example a token that is going to be issued in 10 seconds from now.
func Future(dur time.Duration) TokenValidatorFunc {
	return func(_ []byte, standardClaims Claims, err error) error {
		if errors.Is(err, ErrIssuedInTheFuture) {
			if Clock().Add(dur).Round(time.Second).Unix() < standardClaims.IssuedAt {
				return ErrIssuedInTheFuture
			}

			return nil
		}

		return err
	}
}
