package handler

import (
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/annpolukaro/threat-information-service/internal/api/generated"
)

// создаёт маршрутизатор
func NewRouter(svc ThreatService, apiKey string) http.Handler {
	mux := http.NewServeMux()

	// проверка работоспособности HTTP-сервера.
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})

	handler := NewThreatHandler(svc)

	// REST API: маршруты сгенерированы из OpenAPI
	generated.HandlerWithOptions(
		NewGeneratedAdapter(handler),
		generated.StdHTTPServerOptions{
			BaseRouter: mux,
		},
	)

	// ограничение частоты запросов
	limiter := NewRateLimiter(10, 20)

	// доверяем X-Real-IP только от указанного прокси
	trustedProxy := strings.TrimSpace(
		os.Getenv("TRUSTED_PROXY_CIDR"),
	)

	if trustedProxy != "" {
		if err := limiter.SetTrustedProxies(
			[]string{trustedProxy},
		); err != nil {
			log.Fatalf(
				"invalid TRUSTED_PROXY_CIDR: %v",
				err,
			)
		}
	}

	// API-ключ обязателен для POST и PUT
	protectedRouter := APIKeyMiddleware(apiKey, mux)

	// Rate limiting применяется ко всем запросам
	return limiter.Middleware(protectedRouter)
}
