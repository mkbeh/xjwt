package jwt

import "errors"

var (
	ErrTokenSigned      = errors.New("error token signed")
	ErrInvalidToken     = errors.New("bad token")
	ErrInvalidScheme    = errors.New("invalid scheme")
	ErrInvalidSignature = errors.New("token invalid signature")
	ErrTokenRestriction = errors.New("token restriction")
	ErrTokenExpired     = errors.New("token expired")
)
