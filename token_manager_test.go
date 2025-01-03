package jwt

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

type TestClaims struct {
	jwt.RegisteredClaims
	CustomField string `json:"custom_field"`
}

func TestNew(t *testing.T) {
	_, err := New(WithSecretKey([]byte("secret")))
	assert.NoError(t, err)

	_, err = New(WithSecretKey([]byte("secret")), WithSigningMethod(jwt.SigningMethodHS256))
	assert.NoError(t, err)

	_, err = New()
	assert.Error(t, err)
}

func TestTokenManager_CreateWithClaims(t *testing.T) {
	expiresAtFunc := func(d time.Duration) *jwt.NumericDate {
		e, serr := time.Parse(time.RFC3339, "2053-01-23T10:27:26Z")
		if serr != nil {
			panic(serr)
		}
		return jwt.NewNumericDate(e.Add(d))
	}

	tm, err := New(WithSecretKey([]byte("secret")))
	assert.NoError(t, err)

	testClaims := &TestClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "123",
			ExpiresAt: expiresAtFunc(time.Second * 1),
		},
		CustomField: "test",
	}

	tokenStr, err := tm.CreateWithClaims(testClaims)
	assert.NoError(t, err)

	claims := &TestClaims{}
	perr := tm.ParseWithClaims(fmt.Sprintf("%s %s", scheme, tokenStr), claims)
	assert.NoError(t, perr)

	equalClaims(t, testClaims, claims)
}

func TestTokenManager_ParseWithClaims(t *testing.T) {
	expiresAtFunc := func(d time.Duration) *jwt.NumericDate {
		e, serr := time.Parse(time.RFC3339, "2053-01-23T10:27:26Z")
		if serr != nil {
			panic(serr)
		}
		return jwt.NewNumericDate(e.Add(d))
	}

	tests := []struct {
		name      string
		key       string
		token     string
		expClaims *TestClaims
		expErr    error
	}{
		{
			name:  "valid token",
			key:   "secret",
			token: "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiZXhwIjoyNjIxMjQwODQ3LCJuYW1lIjoiSm9obiBEb2UiLCJpYXQiOjE1MTYyMzkwMjIsImN1c3RvbV9maWVsZCI6InRlc3QxIn0.gxnGdV4oRmmO3_KKUOlnEm-sJZmmlrlIAFVUIMRIZCI",
			expClaims: &TestClaims{
				RegisteredClaims: jwt.RegisteredClaims{
					Subject:   "1234567890",
					ExpiresAt: expiresAtFunc(time.Second * 1),
				},
				CustomField: "test1",
			},
		},
		{
			name:  "valid token - lowercase bearer scheme",
			key:   "secret",
			token: "bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiZXhwIjoyNjIxMjQwODQ3LCJuYW1lIjoiSm9obiBEb2UiLCJpYXQiOjE1MTYyMzkwMjIsImN1c3RvbV9maWVsZCI6InRlc3QxIn0.gxnGdV4oRmmO3_KKUOlnEm-sJZmmlrlIAFVUIMRIZCI",
			expClaims: &TestClaims{
				RegisteredClaims: jwt.RegisteredClaims{
					Subject:   "1234567890",
					ExpiresAt: expiresAtFunc(time.Second * 1),
				},
				CustomField: "test1",
			},
		},
		{
			name:   "error - invalid signature",
			key:    "invalid key",
			token:  "bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiZXhwIjoyNjIxMjQwODQ3LCJuYW1lIjoiSm9obiBEb2UiLCJpYXQiOjE1MTYyMzkwMjIsImN1c3RvbV9maWVsZCI6InRlc3QxIn0.gxnGdV4oRmmO3_KKUOlnEm-sJZmmlrlIAFVUIMRIZCI",
			expErr: ErrInvalidSignature,
		},
		{
			name:   "error - token expired",
			key:    "secret",
			token:  "bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiZXhwIjoxNjIxMjQwODQ3LCJuYW1lIjoiSm9obiBEb2UiLCJpYXQiOjE1MTYyMzkwMjIsImN1c3RvbV9maWVsZCI6InRlc3QxIn0.EMYatmlVgemR2-w9_45dxtIA9zueh_Iy9HXdM4XxsmU",
			expErr: ErrTokenRestriction,
		},
		{
			name:   "error - bad token",
			key:    "secret",
			token:  "bearer aaaaaaaaa",
			expErr: ErrInvalidToken,
		},
		{
			name:   "error - missed bearer scheme",
			key:    "secret",
			token:  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiZXhwIjoyNjIxMjQwODQ3LCJuYW1lIjoiSm9obiBEb2UiLCJpYXQiOjE1MTYyMzkwMjIsImN1c3RvbV9maWVsZCI6InRlc3QxIn0.gxnGdV4oRmmO3_KKUOlnEm-sJZmmlrlIAFVUIMRIZCI",
			expErr: ErrInvalidToken,
		},
		{
			name:   "error - invalid bearer scheme - 1",
			key:    "secret",
			token:  "BearereyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiZXhwIjoyNjIxMjQwODQ3LCJuYW1lIjoiSm9obiBEb2UiLCJpYXQiOjE1MTYyMzkwMjIsImN1c3RvbV9maWVsZCI6InRlc3QxIn0.gxnGdV4oRmmO3_KKUOlnEm-sJZmmlrlIAFVUIMRIZCI",
			expErr: ErrInvalidToken,
		},
		{
			name:   "error - invalid bearer scheme - 2",
			key:    "secret",
			token:  "Bearer123 eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiZXhwIjoyNjIxMjQwODQ3LCJuYW1lIjoiSm9obiBEb2UiLCJpYXQiOjE1MTYyMzkwMjIsImN1c3RvbV9maWVsZCI6InRlc3QxIn0.gxnGdV4oRmmO3_KKUOlnEm-sJZmmlrlIAFVUIMRIZCI",
			expErr: ErrInvalidScheme,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			tm, err := New(WithSecretKey([]byte(tt.key)))
			assert.NoError(t, err)

			claims := &TestClaims{}

			perr := tm.ParseWithClaims(tt.token, claims)
			assert.True(t, errors.Is(perr, tt.expErr), tt.name)

			equalClaims(t, tt.expClaims, claims)
		})
	}
}

func equalClaims(t *testing.T, e, a *TestClaims) {
	if e == nil {
		return
	}

	assert.Equal(t, e.Subject, a.Subject, "equal subject")
	assert.Equal(t, e.ExpiresAt.UTC(), a.ExpiresAt.UTC(), "equal expires at")
	assert.Equal(t, e.CustomField, a.CustomField, "equal custom field")
}
