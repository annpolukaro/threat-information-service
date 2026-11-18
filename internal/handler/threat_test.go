package handler

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCreateInvalidMD5(t *testing.T) {
	router := NewRouter(nil)

	body := `{
		"md5": "invalid",
		"name": "Trojan.Generic"
	}`

	req := httptest.NewRequest(
		http.MethodPost,
		"/info",
		strings.NewReader(body),
	)

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

func TestCreateMissingName(t *testing.T) {
	router := NewRouter(nil)

	body := `{
		"md5": "5d41402abc4b2a76b9719d911017c592"
	}`

	req := httptest.NewRequest(
		http.MethodPost,
		"/info",
		strings.NewReader(body),
	)

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

func TestCreateInvalidJSON(t *testing.T) {
	router := NewRouter(nil)

	req := httptest.NewRequest(
		http.MethodPost,
		"/info",
		strings.NewReader(`{"md5":`),
	)

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

func TestCreateUnknownField(t *testing.T) {
	router := NewRouter(nil)

	body := `{
		"md5": "5d41402abc4b2a76b9719d911017c592",
		"name": "Trojan.Generic",
		"unexpected": "value"
	}`

	req := httptest.NewRequest(
		http.MethodPost,
		"/info",
		strings.NewReader(body),
	)

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

func TestGetInvalidMD5(t *testing.T) {
	router := NewRouter(nil)

	req := httptest.NewRequest(
		http.MethodGet,
		"/info/invalid",
		nil,
	)

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

func TestUpdateInvalidMD5(t *testing.T) {
	router := NewRouter(nil)

	req := httptest.NewRequest(
		http.MethodPut,
		"/info/invalid",
		strings.NewReader(`{"name":"Updated Trojan"}`),
	)

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

func TestUpdateMissingName(t *testing.T) {
	router := NewRouter(nil)

	md5 := "5d41402abc4b2a76b9719d911017c592"

	req := httptest.NewRequest(
		http.MethodPut,
		"/info/"+md5,
		strings.NewReader(`{"severity":"high"}`),
	)

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
}

func TestMethodNotAllowed(t *testing.T) {
	router := NewRouter(nil)

	req := httptest.NewRequest(
		http.MethodDelete,
		"/info/5d41402abc4b2a76b9719d911017c592",
		nil,
	)

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)

	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rec.Code)
	}
}
