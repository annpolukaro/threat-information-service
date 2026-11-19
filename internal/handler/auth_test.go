package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestAPIKeyMiddleware(t *testing.T) {
	tests := []struct {
		name       string
		method     string
		key        string
		wantStatus int
	}{
		{
			name:       "GET without key",
			method:     http.MethodGet,
			wantStatus: http.StatusOK,
		},
		{
			name:       "POST without key",
			method:     http.MethodPost,
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "POST with wrong key",
			method:     http.MethodPost,
			key:        "wrong-key",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "POST with valid key",
			method:     http.MethodPost,
			key:        testAPIKey,
			wantStatus: http.StatusOK,
		},
		{
			name:       "PUT without key",
			method:     http.MethodPut,
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "PUT with wrong key",
			method:     http.MethodPut,
			key:        "wrong-key",
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "PUT with valid key",
			method:     http.MethodPut,
			key:        testAPIKey,
			wantStatus: http.StatusOK,
		},
	}

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	router := APIKeyMiddleware(testAPIKey, next)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, "/info", nil)

			if tt.key != "" {
				req.Header.Set("X-API-Key", tt.key)
			}

			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)

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
