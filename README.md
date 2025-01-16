# JWT Library

This library provides an API for working with [JSON Web Token](https://datatracker.ietf.org/doc/html/rfc7519),
using [jwt-go](https://github.com/golang-jwt/jwt).

## What the heck is a JWT?

JWT.io has [a great introduction](https://jwt.io/introduction) to JSON Web
Tokens.

In short, it's a signed JSON object that does something useful (for example,
authentication). It's commonly used for `Bearer` tokens in Oauth 2. A token is
made of three parts, separated by `.`'s. The first two parts are JSON objects,
that have been [base64url](https://datatracker.ietf.org/doc/html/rfc4648)
encoded. The last part is the signature, encoded the same way.

The first part is called the header. It contains the necessary information for
verifying the last part, the signature. For example, which encryption method
was used for signing and what key was used.

The part in the middle is the interesting bit. It's called the Claims and
contains the actual stuff you care about. Refer to [RFC
7519](https://datatracker.ietf.org/doc/html/rfc7519) for information about
reserved keys and the proper way to add your own.

## Installation Guidelines

1. To install the jwt package, you first need to have
   [Go](https://go.dev/doc/install) installed, then you can use the command
   below to add `jwt-go` as a dependency in your Go program.

```sh
go get -u github.com/mkbeh/xjwt
```

2. Import it in your code:

```go
import "github.com/mkbeh/xjwt"
```

## Usage

A detailed usage guide, including how to sign and verify tokens can be found
in [examples](https://github.com/mkbeh/xjwt/tree/main/examples).

```go
package main

import (
	"fmt"

	"github.com/golang-jwt/jwt/v5"
	tm "github.com/mkbeh/xjwt"
)

func main() {
	tokenManager, err := tm.New(tm.WithSecretKey([]byte("secret")))
	if err != nil {
		panic(err)
	}

	token, err := tokenManager.CreateWithClaims(jwt.MapClaims{"sub": "123"})
	if err != nil {
		panic(err)
	}

	fmt.Printf("token: %s", token)

	claims := jwt.MapClaims{}
	if err := tokenManager.ParseWithClaims(token, claims); err != nil {
		panic(err)
	}

	fmt.Printf("claims: %+v", claims)

}

```