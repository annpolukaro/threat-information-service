package handler

import (
	"crypto/subtle"
	"net/http"
)

func APIKeyMiddleware(apiKey string, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost && r.Method != http.MethodPut {
			next.ServeHTTP(w, r)
			return
		}

		providedKey := r.Header.Get("X-API-Key")

		if apiKey == "" ||
			providedKey == "" ||
			subtle.ConstantTimeCompare(
				[]byte(providedKey),
				[]byte(apiKey),
			) != 1 {
			writeError(
				w,
				http.StatusUnauthorized,
				"Unauthorized",
				"Invalid or missing API key",
			)
			return
		}

		next.ServeHTTP(w, r)
	})
}
