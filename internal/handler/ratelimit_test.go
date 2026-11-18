package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"

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
