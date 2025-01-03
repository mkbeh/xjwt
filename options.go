package jwt

import (
	"github.com/golang-jwt/jwt/v5"
)

// An Option lets you add opts using With* funcs.
type Option interface {
	apply(t *TokenManager)
}

type optionFunc func(t *TokenManager)

func (f optionFunc) apply(t *TokenManager) {
	f(t)
}

func WithSecretKey(key []byte) Option {
	return optionFunc(func(t *TokenManager) {
		t.key = key
	})
}

func WithSigningMethod(method jwt.SigningMethod) Option {
	return optionFunc(func(t *TokenManager) {
		if t.method != nil {
			t.method = method
		}
	})
}
