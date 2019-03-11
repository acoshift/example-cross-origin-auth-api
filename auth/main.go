package main

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"io/ioutil"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/dgrijalva/jwt-go"
)

func main() {
	rsaPrivKey, _ := ioutil.ReadFile("private-key.pem")
	privKey, err := jwt.ParseRSAPrivateKeyFromPEM(rsaPrivKey)
	if err != nil {
		log.Fatal(err)
	}

	auth := &auth{
		PrivateKey: privKey,
	}
	log.Println("Auth Server started at :8081")
	http.ListenAndServe(":8081", auth)
}

type auth struct {
	once sync.Once
	mux  *http.ServeMux

	sessionStorage sync.Map
	PrivateKey     *rsa.PrivateKey
}

type sessionData struct {
	UserID string
}

type errorResponse struct {
	Error string `json:"error"`
}

type successResponse struct {
	Success bool `json:"success"`
}

func (h *auth) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.once.Do(func() {
		h.mux = http.NewServeMux()
		h.mux.HandleFunc("/signin", h.signIn)
		h.mux.HandleFunc("/signout", h.signOut)
		h.mux.HandleFunc("/token", h.token)
	})

	// always return json
	w.Header().Set("Content-Type", "application/json; charset=utf-8")

	// general headers
	w.Header().Set("X-XSS-Protection", "1; mode=block")
	w.Header().Set("X-Frame-Options", "deny")
	w.Header().Set("X-Content-Type-Options", "nosniff")

	// start: CSRF protection

	// validate target
	if r.Host != "localhost:8081" {
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(errorResponse{"CSRF Protection: Invalid host"})
		return
	}

	// validate origin, allow only http://localhost:8080
	if r.Header.Get("Origin") != "http://localhost:8080" {
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(errorResponse{"CSRF Protection: Invalid origin"})
		return
	}

	// validate referer
	if !strings.HasPrefix(r.Header.Get("Referer"), "http://localhost:8080/") {
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(errorResponse{"CSRF Protection: Invalid referer"})
		return
	}

	// end: CSRF protection

	// start: CORS
	// allow only http://localhost:8080
	w.Header().Set("Access-Control-Allow-Origin", "http://localhost:8080")
	w.Header().Set("Access-Control-Allow-Credentials", "true")

	if r.Method == http.MethodOptions {
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-Requested-With")
		w.Header().Set("Access-Control-Max-Age", "3600")
		w.Header().Set("Content-Type", "text/plain")

		// in-case we run behind cached reverse proxy
		w.Header().Add("Vary", "Origin")
		w.Header().Add("Vary", "Access-Control-Request-Method")
		w.Header().Add("Vary", "Access-Control-Request-Headers")

		w.WriteHeader(http.StatusNoContent) // some old browsers might need status 200 or error
		return
	}

	// end: CORS

	// additional CSRF, validate ajax request
	if r.Header.Get("X-Requested-With") != "XMLHttpRequest" {
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(errorResponse{"CSRF Protection: Allow only AJAX requests"})
		return
	}

	h.mux.ServeHTTP(w, r)
}

func (h *auth) signIn(w http.ResponseWriter, r *http.Request) {
	// allow only post
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(errorResponse{"Method not allowed"})
		return
	}

	username := r.PostFormValue("username")
	password := r.PostFormValue("password")
	if username != "miku" || password != "nakano" { // ❤️ Nakano Miku
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(errorResponse{"Invalid credentials"})
		return
	}

	sessID := generateSessionID()
	h.sessionStorage.Store(sessID, sessionData{
		UserID: "miku-001",
	})

	setSessionCookie(w, sessID)
	json.NewEncoder(w).Encode(successResponse{true})
}

func (h *auth) signOut(w http.ResponseWriter, r *http.Request) {
	// allow only post
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(errorResponse{"Method not allowed"})
		return
	}

	// sign out always success
	json.NewEncoder(w).Encode(successResponse{true})

	sessID := h.getSessionID(w, r)
	if sessID != "" {
		h.sessionStorage.Delete(sessID)
	}
}

func (h *auth) token(w http.ResponseWriter, r *http.Request) {
	// allow only get
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET")
		w.WriteHeader(http.StatusMethodNotAllowed)
		json.NewEncoder(w).Encode(errorResponse{"Method not allowed"})
		return
	}

	sessID := h.getSessionID(w, r)
	if sessID == "" {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(errorResponse{"Unauthorized"})
		return
	}

	sessInf, ok := h.sessionStorage.Load(sessID)
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(errorResponse{"Unauthorized"})
		return
	}
	sess := sessInf.(sessionData)

	expIn := 5 * time.Minute
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"sub": sess.UserID,
		"exp": time.Now().Add(expIn).Unix(),
	})
	tokenStr, err := token.SignedString(h.PrivateKey)
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		json.NewEncoder(w).Encode(errorResponse{"Can not sign token"})
		return
	}
	json.NewEncoder(w).Encode(struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
	}{tokenStr, int64(expIn / time.Second)})
}

func (h *auth) getSessionID(w http.ResponseWriter, r *http.Request) string {
	cookie, err := r.Cookie("sess")
	if err != nil {
		// cookie not found
		return ""
	}

	sessID := cookie.Value

	// rolling session expiration
	if sessID != "" {
		setSessionCookie(w, sessID)
	}

	return sessID
}

func generateSessionID() string {
	var b [16]byte
	rand.Read(b[:])
	return base64.RawURLEncoding.EncodeToString(b[:])
}

func setSessionCookie(w http.ResponseWriter, sessID string) {
	http.SetCookie(w, &http.Cookie{
		Name:   "sess",
		Path:   "/",
		Value:  sessID,
		MaxAge: 3600, // 1 hr
		// Secure: true, // for https
		HttpOnly: true, // not allow JavaScript to read session cookie
	})
}
