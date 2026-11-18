package handler

import (
	"net/http"

	"github.com/annpolukaro/threat-information-service/internal/repository"
)

func NewRouter(repo *repository.ThreatRepository) http.Handler {
	mux := http.NewServeMux()
	handler := NewThreatHandler(repo)

	mux.HandleFunc("POST /info", handler.Create)
	mux.HandleFunc("GET /info/{md5}", handler.GetByMD5)
	mux.HandleFunc("PUT /info/{md5}", handler.Update)

	return mux
}
