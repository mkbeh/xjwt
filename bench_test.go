package jwt

import (
	"testing"

	"github.com/golang-jwt/jwt/v5"
)

func BenchmarkTokenManager_CreateWithClaims(b *testing.B) {
	tm, _ := New(WithSecretKey([]byte("secret")))
	claims := jwt.MapClaims{"sub": "test"}
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		tm.CreateWithClaims(claims)
	}
}

func BenchmarkTokenManager_ParseWithClaims(b *testing.B) {
	token := "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwiZXhwIjoyNjIxMjQwODQ3LCJuYW1lIjoiSm9obiBEb2UiLCJpYXQiOjE1MTYyMzkwMjIsImN1c3RvbV9maWVsZCI6InRlc3QxIn0.gxnGdV4oRmmO3_KKUOlnEm-sJZmmlrlIAFVUIMRIZCI" //nolint:gosec // not credentials

	tm, _ := New(WithSecretKey([]byte("secret")))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		tm.ParseWithClaims(token, jwt.MapClaims{})
	}
}
