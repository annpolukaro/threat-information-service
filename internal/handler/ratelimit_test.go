package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/time/rate"
)

func TestRateLimiterAllowsRequests(t *testing.T) {
	limiter := NewRateLimiter(rate.Limit(10), 2)

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := limiter.Middleware(next)

	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodGet, "/info", nil)
		rec := httptest.NewRecorder()

		handler.ServeHTTP(rec, req)

		if rec.Code != http.StatusOK {
			t.Fatalf("request %d: expected 200, got %d", i+1, rec.Code)
		}
	}
}

func TestRateLimiterRejectsExcessRequests(t *testing.T) {
	limiter := NewRateLimiter(rate.Limit(0.001), 1)

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := limiter.Middleware(next)

	first := httptest.NewRecorder()
	handler.ServeHTTP(
		first,
		httptest.NewRequest(http.MethodGet, "/info", nil),
	)

	if first.Code != http.StatusOK {
		t.Fatalf("first request: expected 200, got %d", first.Code)
	}

	second := httptest.NewRecorder()
	handler.ServeHTTP(
		second,
		httptest.NewRequest(http.MethodGet, "/info", nil),
	)

	if second.Code != http.StatusTooManyRequests {
		t.Fatalf(
			"second request: expected 429, got %d",
			second.Code,
		)
	}

	if second.Header().Get("Retry-After") != "1" {
		t.Errorf("expected Retry-After header")
	}
}

func TestRateLimiterDifferentIPs(t *testing.T) {
	limiter := NewRateLimiter(1, 1)

	handler := limiter.Middleware(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		},
	))

	tests := []struct {
		name       string
		ip         string
		wantStatus int
	}{
		{"IP1 first request", "192.168.1.10:1234", http.StatusOK},
		{"IP1 second request", "192.168.1.10:1234", http.StatusTooManyRequests},
		{"IP2 first request", "192.168.1.20:5678", http.StatusOK},
		{"IP2 second request", "192.168.1.20:5678", http.StatusTooManyRequests},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, "/info/test", nil)
			req.RemoteAddr = tt.ip

			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			if rec.Code != tt.wantStatus {
				t.Errorf(
					"expected status %d, got %d",
					tt.wantStatus,
					rec.Code,
				)
			}
		})
	}
}

func TestRateLimiterRetryAfter(t *testing.T) {
	limiter := NewRateLimiter(1, 1)

	handler := limiter.Middleware(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		},
	))

	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodGet, "/info/test", nil)
		req.RemoteAddr = "192.168.1.10:1234"

		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		if i == 1 {
			if rec.Code != http.StatusTooManyRequests {
				t.Fatalf("expected 429, got %d", rec.Code)
			}

			if rec.Header().Get("Retry-After") != "1" {
				t.Errorf("expected Retry-After: 1")
			}
		}
	}
}

func TestRateLimiterCleanup(t *testing.T) {
	limiter := NewRateLimiter(1, 1)

	// Создаём клиента.
	limiter.getLimiter("192.168.1.10")

	// Имитируем, что клиент неактивен более 10 минут.
	limiter.mu.Lock()
	limiter.clients["192.168.1.10"].lastSeen = time.Now().Add(-11 * time.Minute)
	limiter.lastCleanup = time.Now().Add(-2 * time.Minute)
	limiter.mu.Unlock()

	// Запускаем очистку через запрос другого клиента.
	limiter.getLimiter("192.168.1.20")

	limiter.mu.Lock()
	_, exists := limiter.clients["192.168.1.10"]
	limiter.mu.Unlock()

	if exists {
		t.Error("inactive client was not removed")
	}
}
