package main

import (
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"sync"

	"github.com/dgrijalva/jwt-go"
)

func main() {
	pubKey, _ := ioutil.ReadFile("public-key.pem")
	publicKey, err := jwt.ParseRSAPublicKeyFromPEM(pubKey)
	if err != nil {
		log.Fatal(err)
	}

	api := &api{
		PublicKey: publicKey,
	}
	log.Println("API Server started at :8082")
	http.ListenAndServe(":8082", api)
}

type api struct {
	once sync.Once
	mux  *http.ServeMux

	PublicKey *rsa.PublicKey
}

type errorResponse struct {
	Error string `json:"error"`
}

func (h *api) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.once.Do(func() {
		h.mux = http.NewServeMux()
		h.mux.HandleFunc("/profile", h.profile)
	})

	// always return json
	w.Header().Set("Content-Type", "application/json; charset=utf-8")

	// general headers
	w.Header().Set("X-XSS-Protection", "1; mode=block")
	w.Header().Set("X-Frame-Options", "deny")
	w.Header().Set("X-Content-Type-Options", "nosniff")

	// start: CORS

	// allow all origins
	w.Header().Set("Access-Control-Allow-Origin", "*")
	// not allow credentials

	if r.Method == http.MethodOptions {
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		w.Header().Set("Access-Control-Max-Age", "3600")
		w.Header().Set("Content-Type", "text/plain")

		// in-case we run behind cached reverse proxy
		w.Header().Add("Vary", "Origin")
		w.Header().Add("Vary", "Access-Control-Request-Method")
		w.Header().Add("Vary", "Access-Control-Request-Headers")

		w.WriteHeader(http.StatusNoContent)
		return
	}

	// end: CORS

	h.mux.ServeHTTP(w, r)
}

func (h *api) profile(w http.ResponseWriter, r *http.Request) {
	subject := h.parseToken(r)
	if subject == "" {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(errorResponse{"Unauthorized"})
		return
	}

	json.NewEncoder(w).Encode(struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}{subject, "Nakano Miku"})
}

// parseToken parses token from request and return user's id
func (h *api) parseToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if len(auth) < 7 {
		return ""
	}

	if !strings.EqualFold(auth[:7], "bearer ") {
		return ""
	}

	tokenStr := auth[7:]
	if tokenStr == "" {
		return ""
	}

	token, err := jwt.ParseWithClaims(tokenStr, jwt.MapClaims{}, func(token *jwt.Token) (interface{}, error) {
		if token.Method != jwt.SigningMethodRS256 {
			return nil, fmt.Errorf("invalid method")
		}
		return h.PublicKey, nil
	})
	if err != nil {
		return ""
	}
	if !token.Valid {
		return ""
	}

	sub, _ := token.Claims.(jwt.MapClaims)["sub"].(string)
	return sub
}
