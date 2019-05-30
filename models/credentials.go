package models

import "github.com/dgrijalva/jwt-go"

// Credentials Struct
type Credentials struct {
	Password string `json:"password"`
	Username string `json:"username"`
}

// Claims Struct
type Claims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

// TokenData Struct
type TokenData struct {
	Value     string
	Expiresin string
}
