package http

import (
	"context"
	"net/http"
	"strings"

	"github.com/BigMoneyBigSuccess/cineMate/clients"
)

func AuthMiddleware(authClient *clients.AuthClient, requiredAuth bool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			
			authHeader := r.Header.Get("Authorization")
			if authHeader == "" {
				if requiredAuth {
					writeErrorResponse(w, "unauthenticated", "authorization header is required")
					return
				}
				next.ServeHTTP(w, r)
				return
			}

			
			parts := strings.SplitN(authHeader, " ", 2)
			if len(parts) != 2 || parts[0] != "Bearer" {
				writeErrorResponse(w, "unauthenticated", "invalid authorization header format")
				return
			}

			token := parts[1]

			
			userID, valid, errMsg := authClient.ValidateToken(r.Context(), token)
			if !valid {
				if errMsg != "" {
					writeErrorResponse(w, "unauthenticated", errMsg)
				} else {
					writeErrorResponse(w, "unauthenticated", "invalid token")
				}
				return
			}

			
			ctx := context.WithValue(r.Context(), "user_id", userID.String())
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func CORSMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		next.ServeHTTP(w, r)
	})
}

func writeErrorResponseString(w http.ResponseWriter, code string, message string) {
	var statusCode int
	switch code {
	case "invalid_argument":
		statusCode = http.StatusBadRequest
	case "not_found":
		statusCode = http.StatusNotFound
	case "already_exists":
		statusCode = http.StatusConflict
	case "unauthenticated":
		statusCode = http.StatusUnauthorized
	case "permission_denied":
		statusCode = http.StatusForbidden
	default:
		statusCode = http.StatusInternalServerError
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	w.Write([]byte(`{"error":"` + message + `"}`))
}

func writeErrorResponse(w http.ResponseWriter, code string, message string) {
	writeErrorResponseString(w, code, message)
}
