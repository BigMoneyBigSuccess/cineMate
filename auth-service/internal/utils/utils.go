package utils

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

var jwtSecret []byte

func LoadJWTSecret() error {
	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		return errors.New("JWT_SECRET environment variable is required")
	}
	jwtSecret = []byte(secret)
	return nil
}

func GenerateJWT(userID string) (string, error) {
	if len(jwtSecret) == 0 {
		return "", errors.New("jwt secret not loaded")
	}

	if _, err := uuid.Parse(userID); err != nil {
		return "", errors.New("invalid user_id")
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": userID,
		"exp":     time.Now().Add(24 * time.Hour).Unix(),
	})

	return token.SignedString(jwtSecret)
}

func ParseJWT(tokenStr string) (uuid.UUID, error) {
	if len(jwtSecret) == 0 {
		return uuid.Nil, errors.New("jwt secret not loaded")
	}

	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return jwtSecret, nil
	})

	if err != nil || !token.Valid {
		return uuid.Nil, errors.New("invalid token")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return uuid.Nil, errors.New("invalid token claims")
	}

	userIDValue, ok := claims["user_id"].(string)
	if !ok {
		return uuid.Nil, errors.New("invalid token user_id")
	}

	userID, err := uuid.Parse(userIDValue)
	if err != nil {
		return uuid.Nil, errors.New("invalid token user_id")
	}

	return userID, nil
}

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

func CheckPassword(hash, password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}
