package handler

import (
	"net/http"
)

func NewRouter(repo ThreatRepository) http.Handler {
	mux := http.NewServeMux()
	handler := NewThreatHandler(repo)

	mux.HandleFunc("POST /info", handler.Create)
	mux.HandleFunc("GET /info/{md5}", handler.GetByMD5)
	mux.HandleFunc("PUT /info/{md5}", handler.Update)

	limiter := NewRateLimiter(10, 20)

	return limiter.Middleware(mux)
}
