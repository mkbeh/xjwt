# xjwt

Lightweight wrapper around [golang-jwt/jwt](https://github.com/golang-jwt/jwt)
that provides a clean API for creating and validating JSON Web Tokens.

## What is a JWT?

JWT.io has [a great introduction](https://jwt.io/introduction) to JSON Web Tokens.

In short, it's a signed JSON object used for secure data exchange between parties.
Commonly used for `Bearer` tokens in OAuth 2.0. A token consists of three
base64url-encoded parts separated by `.`:

- **Header** — signing algorithm and token type
- **Claims** — the payload: subject, expiration, custom fields, etc.
- **Signature** — verifies the token hasn't been tampered with

See [RFC 7519](https://datatracker.ietf.org/doc/html/rfc7519) for the full spec.

## Requirements

- Go 1.21+

## Installation

```sh
go get github.com/mkbeh/xjwt
```

## Quick Start

```go
package main

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/mkbeh/xjwt"
)

type MyClaims struct {
	jwt.RegisteredClaims
	UserID string `json:"user_id"`
}

func main() {
	manager, err := xjwt.New(xjwt.WithSecretKey([]byte("secret")))
	if err != nil {
		panic(err)
	}

	// Create token
	token, err := manager.CreateWithClaims(&MyClaims{
		UserID: "42",
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: xjwt.AddExpiresAt(time.Hour),
		},
	})
	if err != nil {
		panic(err)
	}

	fmt.Println("token:", token)

	// Parse and validate token
	claims := &MyClaims{}
	if err := manager.ParseWithClaims("Bearer "+token, claims); err != nil {
		panic(err)
	}

	fmt.Printf("user_id: %s\n", claims.UserID)
}
```

## Configuration

| Option                                 | Default  | Description       |
|----------------------------------------|----------|-------------------|
| `WithSecretKey([]byte)`                | required | HMAC secret key   |
| `WithSigningMethod(jwt.SigningMethod)` | `HS256`  | Signing algorithm |

## Error Handling

```go
import "errors"

err := manager.ParseWithClaims(tokenString, claims)
switch {
case errors.Is(err, xjwt.ErrInvalidToken):
// malformed or missing token
case errors.Is(err, xjwt.ErrInvalidScheme):
// missing or wrong scheme (expected Bearer)
case errors.Is(err, xjwt.ErrTokenExpired):
// token is expired
case errors.Is(err, xjwt.ErrInvalidSignature):
// signature mismatch
}
```

## Examples

More examples can be found in [/examples](https://github.com/mkbeh/xjwt/tree/main/examples).

## License

[MIT](LICENSE)