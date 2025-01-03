package jwt

import (
	"errors"
	"fmt"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

const (
	scheme = "bearer"
)

type TokenManager struct {
	key    []byte
	method jwt.SigningMethod
}

func New(opts ...Option) (*TokenManager, error) {
	t := &TokenManager{
		method: jwt.SigningMethodHS256,
	}

	for _, opt := range opts {
		opt.apply(t)
	}

	if len(t.key) == 0 {
		return nil, fmt.Errorf("secret key must be set, use With* option")
	}

	return t, nil
}

// CreateWithClaims creates and returns a complete, signed JWT.
func (t *TokenManager) CreateWithClaims(claims jwt.Claims) (string, error) {
	token := jwt.NewWithClaims(t.method, claims)

	s, err := token.SignedString(t.key)
	if err != nil {
		return "", fmt.Errorf("%w: %w", ErrTokenSigned, err)
	}

	return s, nil
}

// ParseWithClaims parses, validates, verifies the signature and returns the parsed expClaims.
func (t *TokenManager) ParseWithClaims(tokenString string, claims jwt.Claims) error {
	splits := strings.SplitN(tokenString, " ", 2)
	if len(splits) < 2 {
		return fmt.Errorf("%w: split token string < 2", ErrInvalidToken)
	}

	if !strings.EqualFold(splits[0], scheme) {
		return fmt.Errorf("%w: token string must contains bearer scheme", ErrInvalidScheme)
	}

	token, err := jwt.ParseWithClaims(splits[1], claims, func(_ *jwt.Token) (interface{}, error) { return t.key, nil })
	if err != nil {
		switch {
		case errors.Is(err, jwt.ErrSignatureInvalid):
			return fmt.Errorf("%w: %w", ErrInvalidSignature, err)
		case errors.Is(err, jwt.ErrTokenInvalidClaims):
			return fmt.Errorf("%w: %w", ErrTokenRestriction, err)
		default:
			return fmt.Errorf("%w: %w", ErrInvalidToken, err)
		}
	}

	if !token.Valid {
		return fmt.Errorf("%w: invalid token", ErrInvalidToken)
	}

	return nil
}
