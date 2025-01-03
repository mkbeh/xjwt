package main

import (
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	tm "github.com/mkbeh/jwt"
)

var tokenManager *tm.TokenManager

type TestClaims struct {
	jwt.RegisteredClaims
	CustomField string `json:"custom_field"`
}

func createTokensHandler(w http.ResponseWriter, r *http.Request) {
	claims := &TestClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "123",
			ExpiresAt: tm.AddExpiresAt(time.Minute * 15),
		},
		CustomField: "test",
	}

	token, err := tokenManager.CreateWithClaims(claims)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(token))
}

func parseTokenHandler(w http.ResponseWriter, r *http.Request) {
	token := r.Header.Get("Authorization")
	claims := &TestClaims{}

	if err := tokenManager.ParseWithClaims(token, claims); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	payload, err := json.Marshal(claims)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(payload)
}

func main() {
	var err error

	tokenManager, err = tm.New(tm.WithSecretKey([]byte("secret")))
	if err != nil {
		log.Fatal(err)
	}

	http.HandleFunc("/create_token", createTokensHandler)
	http.HandleFunc("/parse_token", parseTokenHandler)

	if err := http.ListenAndServe("localhost:8080", nil); err != nil {
		log.Fatalln("Unable to start web server:", err)
	}
}
