package handler

import (
	"encoding/json"
	"net/http"

	"golang.org/x/time/rate"
)

type RateLimiter struct {
	limiter *rate.Limiter
}

func NewRateLimiter(requestsPerSecond rate.Limit, burst int) *RateLimiter {
	return &RateLimiter{
		limiter: rate.NewLimiter(requestsPerSecond, burst),
	}
}

func (r *RateLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if !r.limiter.Allow() {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)

			_ = json.NewEncoder(w).Encode(map[string]string{
				"message": "Too many requests",
			})
			return
		}

		next.ServeHTTP(w, req)
	})
}
