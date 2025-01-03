package jwt

import (
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// AddExpiresAt add expires at.
// In JWT, the expiry time is expressed as unix milliseconds.
func AddExpiresAt(lifetime time.Duration) *jwt.NumericDate {
	return jwt.NewNumericDate(time.Now().Add(lifetime))
}
