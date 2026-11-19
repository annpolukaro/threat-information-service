package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestClientIPWithoutTrustedProxy(t *testing.T) {
	limiter := NewRateLimiter(10, 20)

	req := httptest.NewRequest(http.MethodGet, "/info/test", nil)
	req.RemoteAddr = "192.168.1.100:12345"
	req.Header.Set("X-Real-IP", "8.8.8.8")

	got := limiter.clientIP(req)
	want := "192.168.1.100"

	if got != want {
		t.Errorf("clientIP() = %q, want %q", got, want)
	}
}

func TestClientIPWithTrustedProxy(t *testing.T) {
	limiter := NewRateLimiter(10, 20)

	err := limiter.SetTrustedProxies([]string{
		"172.30.10.10/32",
	})
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/info/test", nil)
	req.RemoteAddr = "172.30.10.10:54321"
	req.Header.Set("X-Real-IP", "192.168.1.100")

	got := limiter.clientIP(req)
	want := "192.168.1.100"

	if got != want {
		t.Errorf("clientIP() = %q, want %q", got, want)
	}
}

func TestClientIPRejectsSpoofedHeader(t *testing.T) {
	limiter := NewRateLimiter(10, 20)

	err := limiter.SetTrustedProxies([]string{
		"172.30.10.10/32",
	})
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/info/test", nil)
	req.RemoteAddr = "192.168.1.100:12345"
	req.Header.Set("X-Real-IP", "8.8.8.8")

	got := limiter.clientIP(req)
	want := "192.168.1.100"

	if got != want {
		t.Errorf("spoofed header accepted: got %q, want %q", got, want)
	}
}

func TestClientIPInvalidForwardedIP(t *testing.T) {
	limiter := NewRateLimiter(10, 20)

	err := limiter.SetTrustedProxies([]string{
		"172.30.10.10/32",
	})
	if err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/info/test", nil)
	req.RemoteAddr = "172.30.10.10:54321"
	req.Header.Set("X-Real-IP", "not-an-ip")

	got := limiter.clientIP(req)
	want := "172.30.10.10"

	if got != want {
		t.Errorf("clientIP() = %q, want %q", got, want)
	}
}

func TestSetTrustedProxiesInvalidCIDR(t *testing.T) {
	limiter := NewRateLimiter(10, 20)

	err := limiter.SetTrustedProxies([]string{
		"invalid-cidr",
	})

	if err == nil {
		t.Fatal("expected error for invalid CIDR")
	}
}

func TestRateLimiterDifferentClientsBehindProxy(t *testing.T) {
	limiter := NewRateLimiter(1, 1)

	err := limiter.SetTrustedProxies([]string{
		"172.30.10.10/32",
	})
	if err != nil {
		t.Fatal(err)
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := limiter.Middleware(next)

	sendRequest := func(clientIP string) int {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.RemoteAddr = "172.30.10.10:54321"
		req.Header.Set("X-Real-IP", clientIP)

		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)

		return rec.Code
	}

	if got := sendRequest("192.168.1.1"); got != http.StatusOK {
		t.Fatalf("first client: got %d, want 200", got)
	}

	if got := sendRequest("192.168.1.1"); got != http.StatusTooManyRequests {
		t.Fatalf("same client: got %d, want 429", got)
	}

	if got := sendRequest("192.168.1.2"); got != http.StatusOK {
		t.Fatalf("different client: got %d, want 200", got)
	}
}
