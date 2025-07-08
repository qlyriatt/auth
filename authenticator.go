package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"golang.org/x/crypto/bcrypt"
)

var webhook = os.Getenv("WEBHOOK")

var (
	secret    = []byte(os.Getenv("JWT_SECRET"))
	db_       *pgx.Conn
	blacklist = make(map[string]time.Time)
)

type JtiClaims struct {
	Jti string `json:"jti"`
	jwt.RegisteredClaims
}

// jwt sha512 string
func generateAccessToken(id string) (string, error) {

	claims := JtiClaims{
		Jti: uuid.NewString(),
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   id,
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(10 * time.Minute)),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)

	return token.SignedString(secret)
}

// rand 32 []byte
func generateRefreshToken() []byte {

	token := make([]byte, 32)
	rand.Read(token)

	return token
}

func verifyAccessToken(token string) (JtiClaims, error) {

	var claims JtiClaims

	t, err := jwt.ParseWithClaims(token, &claims, func(t *jwt.Token) (interface{}, error) { return secret, nil })
	if err != nil || !t.Valid {
		return JtiClaims{}, err
	}

	if _, ok := blacklist[claims.Jti]; ok {
		return JtiClaims{}, errors.New("access token blacklisted")
	}

	return claims, nil
}

// return custom Claims after parsing & verification
func claimsFromRequestVerify(r *http.Request) (JtiClaims, error) {
	auth_header := r.Header.Get("Authorization")
	if auth_header == "" || !strings.HasPrefix(auth_header, "Bearer ") {
		return JtiClaims{}, errors.New("missing or invalid Authorization header")
	}

	return verifyAccessToken(strings.TrimPrefix(auth_header, "Bearer "))
}

func authHandler(w http.ResponseWriter, r *http.Request) {

	var req struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.ID == "" {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	access_token, err := generateAccessToken(req.ID)
	if err != nil {
		http.Error(w, "Error generating token", http.StatusInternalServerError)
		return
	}

	refresh_token := generateRefreshToken()
	refresh_hash, err := bcrypt.GenerateFromPassword(refresh_token, bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Error hashing refresh token", http.StatusInternalServerError)
		return
	}

	// db storage
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	_, err = db_.Exec(context.Background(),
		"INSERT INTO users (id, ip, user_agent, refresh_hash) VALUES ($1, $2, $3, $4)",
		req.ID, ip, r.Header.Get("User-Agent"), refresh_hash)
	if err != nil {
		log.Println(err)
	}

	resp := map[string]string{
		"access_token":  access_token,
		"refresh_token": base64.StdEncoding.EncodeToString(refresh_token),
	}

	json.NewEncoder(w).Encode(resp)
}

func refreshHandler(w http.ResponseWriter, r *http.Request) {

	claims, err := claimsFromRequestVerify(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	var req struct {
		Token string `json:"refresh_token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Token == "" {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}

	// current user data
	var (
		id           string
		ip           string
		user_agent   string
		refresh_hash []byte
	)
	err = db_.QueryRow(context.Background(),
		"SELECT id, ip::text, user_agent, refresh_hash FROM users WHERE id=$1", claims.Subject).Scan(&id, &ip, &user_agent, &refresh_hash)
	if err != nil {
		log.Println(err)
	}

	// ban user agent change
	if r.Header.Get("User-Agent") != user_agent {
		log.Println(r.Header.Get("User-Agent"), "...", user_agent)
		blacklist[claims.Jti] = claims.ExpiresAt.Time
		db_.Exec(context.Background(), "DELETE FROM users WHERE id=$1", claims.Subject)
		http.Error(w, "User Agent Changed", http.StatusForbidden)
		return
	}

	// send post to webhook on ip change
	if new_ip, _, _ := net.SplitHostPort(r.RemoteAddr); new_ip != ip {
		db_.Exec(context.Background(), "UPDATE users SET ip=$1 WHERE id=$2", new_ip, id)
		http.Post(webhook, "text/plain", bytes.NewBufferString("authenticated user changed ip"))
	}

	refresh_token, err := base64.StdEncoding.DecodeString(req.Token)
	if err != nil {
		http.Error(w, "Invalid refresh token", http.StatusForbidden)
		return
	}
	if bcrypt.CompareHashAndPassword(refresh_hash, refresh_token) != nil {
		http.Error(w, "Invalid refresh token", http.StatusForbidden)
		return
	}

	new_access_token, err := generateAccessToken(id)
	if err != nil {
		http.Error(w, "Error generating token", http.StatusInternalServerError)
		return
	}
	new_refresh_token := generateRefreshToken()
	new_refresh_hash, err := bcrypt.GenerateFromPassword([]byte(new_refresh_token), bcrypt.DefaultCost)
	if err != nil {
		http.Error(w, "Error hashing refresh token", http.StatusInternalServerError)
		return
	}

	_, err = db_.Exec(context.Background(), "UPDATE users SET refresh_hash=$1 WHERE id=$2", new_refresh_hash, id)
	if err != nil {
		log.Println(err)
	}

	resp := map[string]string{
		"access_token":  new_access_token,
		"refresh_token": base64.StdEncoding.EncodeToString(new_refresh_token),
	}
	json.NewEncoder(w).Encode(resp)
}

func idHandler(w http.ResponseWriter, r *http.Request) {

	claims, err := claimsFromRequestVerify(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	json.NewEncoder(w).Encode(map[string]string{"id": claims.Subject})
}

func unauthHandler(w http.ResponseWriter, r *http.Request) {

	claims, err := claimsFromRequestVerify(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusUnauthorized)
		return
	}

	// blacklist access token until expiration
	blacklist[claims.Jti] = claims.ExpiresAt.Time
	db_.Exec(context.Background(), "DELETE FROM users WHERE id=$1", claims.Subject)

	w.WriteHeader(http.StatusOK)
}

func main() {

	db_url := fmt.Sprintf("postgres://%s:%s@%s:5432/%s",
		os.Getenv("POSTGRES_USER"), os.Getenv("POSTGRES_PASSWORD"), os.Getenv("POSTGRES_HOST"), os.Getenv("POSTGRES_DB"))

	var err error
	db_, err = pgx.Connect(context.Background(), db_url)
	if err != nil {
		log.Fatal("db connection error: ", err)
	}
	defer db_.Close(context.Background())

	_, err = db_.Exec(context.Background(),
		`CREATE TABLE IF NOT EXISTS users (
    		id UUID PRIMARY KEY,
    		ip INET NOT NULL,
    		user_agent TEXT NOT NULL,
    		refresh_hash BYTEA NOT NULL
		);`)

	if err != nil {
		log.Fatal(err)
	}

	http.HandleFunc("/auth", authHandler)
	http.HandleFunc("/refresh", refreshHandler)
	http.HandleFunc("/id", idHandler)
	http.HandleFunc("/unauth", unauthHandler)

	log.Println("Server running on :8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
