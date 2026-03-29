package utils

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

var (
	privateKeyRSA *rsa.PrivateKey
	pubKey        *rsa.PublicKey
	once          sync.Once
)

func LoadKeys() error {
	var err error
	once.Do(func() {
		privPath := os.Getenv("PRIVATE_KEY_PATH")
		pubPath := os.Getenv("PUBLIC_KEY_PATH")

		privData, e := os.ReadFile(privPath)
		if e != nil {
			err = e
			return
		}
		pubData, e := os.ReadFile(pubPath)
		if e != nil {
			err = e
			return
		}

		priv, e := jwt.ParseRSAPrivateKeyFromPEM(privData)
		if e != nil {
			err = e
			return
		}
		pub, e := jwt.ParseRSAPublicKeyFromPEM(pubData)
		if e != nil {
			err = e
			return
		}

		privateKeyRSA = priv
		pubKey = pub
	})
	return err
}

func GenerateJWT(userID int64) (string, error) {
	if privateKeyRSA == nil {
		return "", errors.New("private key not loaded")
	}

	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"user_id": userID,
		"exp":     time.Now().Add(time.Hour * 24).Unix(),
	})

	return token.SignedString(privateKeyRSA)
}

func ParseJWT(tokenStr string) (int64, error) {
	if pubKey == nil {
		return 0, errors.New("public key not loaded")
	}

	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}

		return pubKey, nil
	})

	if err != nil || !token.Valid {
		return 0, errors.New("invalid token")
	}

	claims := token.Claims.(jwt.MapClaims)
	return claims["user_id"].(int64), nil
}

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func CheckPassword(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}
