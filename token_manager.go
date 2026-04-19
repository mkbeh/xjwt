package jwt

import (
	"errors"
	"fmt"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

const (
	bearerScheme = "bearer"
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
	rawToken, err := extractBearerToken(tokenString)
	if err != nil {
		return err
	}

	token, err := jwt.ParseWithClaims(rawToken, claims, func(token *jwt.Token) (interface{}, error) {
		if token.Method.Alg() != t.method.Alg() {
			return nil, fmt.Errorf("%w: unexpected signing method %q", ErrInvalidSignature, token.Header["alg"])
		}
		return t.key, nil
	})
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

func extractBearerToken(tokenString string) (string, error) {
	scheme, token, found := strings.Cut(tokenString, " ")
	if !found {
		return "", fmt.Errorf("%w: missing scheme", ErrInvalidToken)
	}
	if !strings.EqualFold(scheme, bearerScheme) {
		return "", fmt.Errorf("%w: expected bearer scheme", ErrInvalidScheme)
	}
	return token, nil
}
