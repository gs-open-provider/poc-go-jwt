package services

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gs-open-provider/poc-go-jwt/internal/logger"
	"github.com/gs-open-provider/poc-go-jwt/mock"
	"github.com/gs-open-provider/poc-go-jwt/models"
	"github.com/spf13/viper"
)

// Create the JWT key used to create the signature
var jwtKey = []byte(viper.GetString("jwtSecret"))

// HandleSignin Function
func HandleSignin(w http.ResponseWriter, r *http.Request) {
	var creds models.Credentials
	err := json.NewDecoder(r.Body).Decode(&creds)
	if err != nil {
		logger.Log.Error(err.Error())
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	expectedPassword, ok := mock.Users[creds.Username]
	if !ok || expectedPassword != creds.Password {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	expirationTime := time.Now().Add(1 * time.Minute)
	claims := &models.Claims{
		Username: creds.Username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		logger.Log.Error(err.Error())
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	logger.Log.Info(tokenString)
	http.SetCookie(w, &http.Cookie{
		Name:    "token",
		Value:   tokenString,
		Expires: expirationTime,
		Secure:  true,
	})

	data := models.TokenData{
		Value:     tokenString,
		Expiresin: expirationTime.String(),
	}
	json.NewEncoder(w).Encode(data)
}

// HandleWelcome Function
func HandleWelcome(w http.ResponseWriter, r *http.Request) {
	accessToken := r.Header.Get("Authorization")
	tknStr := strings.Split(accessToken, " ")[1]
	logger.Log.Info(tknStr)

	claims := &models.Claims{}
	tkn, err := jwt.ParseWithClaims(tknStr, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})
	if !tkn.Valid {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	logger.Log.Info("Welcome %s!" + claims.Username)
	json.NewEncoder(w).Encode(claims)
}

// HandleRefresh Function
func HandleRefresh(w http.ResponseWriter, r *http.Request) {
	accessToken := r.Header.Get("Authorization")
	tknStr := strings.Split(accessToken, " ")[1]
	logger.Log.Info(tknStr)

	claims := &models.Claims{}
	tkn, err := jwt.ParseWithClaims(tknStr, claims, func(token *jwt.Token) (interface{}, error) {
		return jwtKey, nil
	})
	if !tkn.Valid {
		logger.Log.Error("Unauthorized.. Trying to Refresh Token..")
	}
	if err != nil && !strings.Contains(err.Error(), "token is expired") {
		logger.Log.Error(err.Error())
		if err == jwt.ErrSignatureInvalid {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	// if (CURRENT TIME - EXPIRATION TIME) is GREATER THAN the ACCEPTED DURATION ==> Consider as a BAD REQUEST
	if time.Now().Sub(time.Unix(claims.ExpiresAt, 0)) > 5*time.Minute {
		logger.Log.Info("Expired, and delay is MORE than expected..")
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	logger.Log.Info("Expired, but delay is LESS than expected..")

	expirationTime := time.Now().Add(1 * time.Minute)
	claims.ExpiresAt = expirationTime.Unix()
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	data := models.TokenData{
		Value:     tokenString,
		Expiresin: expirationTime.String(),
	}
	json.NewEncoder(w).Encode(data)

}
