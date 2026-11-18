package handler

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/annpolukaro/threat-information-service/internal/domain"
	"github.com/annpolukaro/threat-information-service/internal/repository"
)

const testMD5 = "5d41402abc4b2a76b9719d911017c592"

type mockThreatRepository struct {
	threats map[string]*domain.Threat
	err     error
}

func newMockThreatRepository() *mockThreatRepository {
	return &mockThreatRepository{threats: make(map[string]*domain.Threat)}
}

func (m *mockThreatRepository) Create(_ context.Context, threat *domain.Threat) error {
	if m.err != nil {
		return m.err
	}
	if _, exists := m.threats[threat.MD5]; exists {
		return repository.ErrConflict
	}
	m.threats[threat.MD5] = threat
	return nil
}

func (m *mockThreatRepository) GetByMD5(_ context.Context, md5 string) (*domain.Threat, error) {
	if m.err != nil {
		return nil, m.err
	}
	threat, exists := m.threats[md5]
	if !exists {
		return nil, repository.ErrNotFound
	}
	return threat, nil
}

func (m *mockThreatRepository) Update(_ context.Context, threat *domain.Threat) error {
	if m.err != nil {
		return m.err
	}
	if _, exists := m.threats[threat.MD5]; !exists {
		return repository.ErrNotFound
	}
	m.threats[threat.MD5] = threat
	return nil
}

func sendRequest(t *testing.T, router http.Handler, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

func assertStatus(t *testing.T, rec *httptest.ResponseRecorder, want int) {
	t.Helper()
	if rec.Code != want {
		t.Fatalf("expected status %d, got %d: %s", want, rec.Code, rec.Body.String())
	}
}

func readThreat(t *testing.T, rec *httptest.ResponseRecorder) domain.Threat {
	t.Helper()
	var threat domain.Threat
	if err := json.Unmarshal(rec.Body.Bytes(), &threat); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return threat
}

func TestCreateThreat(t *testing.T) {
	repo := newMockThreatRepository()
	router := NewRouter(repo)
	body := `{"md5":"5d41402abc4b2a76b9719d911017c592","name":"Test Trojan","description":"Test malware","threat_type":"trojan","severity":"high"}`
	rec := sendRequest(t, router, http.MethodPost, "/info", body)
	assertStatus(t, rec, http.StatusCreated)
	threat := readThreat(t, rec)
	if threat.MD5 != testMD5 || threat.Name != "Test Trojan" || threat.Description != "Test malware" || threat.ThreatType != domain.ThreatTypeTrojan || threat.Severity != domain.SeverityHigh {
		t.Errorf("unexpected threat: %+v", threat)
	}
	if _, exists := repo.threats[testMD5]; !exists {
		t.Error("threat was not saved")
	}
}

func TestGetThreat(t *testing.T) {
	repo := newMockThreatRepository()
	repo.threats[testMD5] = &domain.Threat{MD5: testMD5, Name: "Test Trojan", Description: "Test malware", ThreatType: domain.ThreatTypeTrojan, Severity: domain.SeverityHigh}
	rec := sendRequest(t, NewRouter(repo), http.MethodGet, "/info/"+testMD5, "")
	assertStatus(t, rec, http.StatusOK)
	threat := readThreat(t, rec)
	if threat.MD5 != testMD5 || threat.Name != "Test Trojan" || threat.Severity != domain.SeverityHigh {
		t.Errorf("unexpected threat: %+v", threat)
	}
}

func TestUpdateThreat(t *testing.T) {
	repo := newMockThreatRepository()
	repo.threats[testMD5] = &domain.Threat{MD5: testMD5, Name: "Old Trojan", ThreatType: domain.ThreatTypeTrojan, Severity: domain.SeverityLow}
	body := `{"name":"Updated Trojan","description":"Updated malware description","threat_type":"trojan","severity":"critical"}`
	rec := sendRequest(t, NewRouter(repo), http.MethodPut, "/info/"+testMD5, body)
	assertStatus(t, rec, http.StatusOK)
	threat := readThreat(t, rec)
	if threat.Name != "Updated Trojan" || threat.Description != "Updated malware description" || threat.Severity != domain.SeverityCritical {
		t.Errorf("unexpected threat: %+v", threat)
	}
	if repo.threats[testMD5].Name != "Updated Trojan" {
		t.Error("threat was not updated")
	}
}

func TestCreateThreatConflict(t *testing.T) {
	repo := newMockThreatRepository()
	repo.threats[testMD5] = &domain.Threat{MD5: testMD5, Name: "Existing Trojan"}
	body := `{"md5":"5d41402abc4b2a76b9719d911017c592","name":"New Trojan","threat_type":"trojan","severity":"high"}`
	rec := sendRequest(t, NewRouter(repo), http.MethodPost, "/info", body)
	assertStatus(t, rec, http.StatusConflict)
	if repo.threats[testMD5].Name != "Existing Trojan" {
		t.Error("existing threat was overwritten")
	}
}

func TestGetThreatNotFound(t *testing.T) {
	rec := sendRequest(t, NewRouter(newMockThreatRepository()), http.MethodGet, "/info/"+testMD5, "")
	assertStatus(t, rec, http.StatusNotFound)
}

func TestUpdateThreatNotFound(t *testing.T) {
	body := `{"name":"Updated Trojan","threat_type":"trojan","severity":"high"}`
	rec := sendRequest(t, NewRouter(newMockThreatRepository()), http.MethodPut, "/info/"+testMD5, body)
	assertStatus(t, rec, http.StatusNotFound)
}

func TestCreateInvalidMD5(t *testing.T) {
	body := `{"md5":"invalid","name":"Test Trojan"}`
	rec := sendRequest(t, NewRouter(newMockThreatRepository()), http.MethodPost, "/info", body)
	assertStatus(t, rec, http.StatusBadRequest)
}

func TestCreateInvalidJSON(t *testing.T) {
	rec := sendRequest(t, NewRouter(newMockThreatRepository()), http.MethodPost, "/info", `{"md5":`)
	assertStatus(t, rec, http.StatusBadRequest)
}

func TestCreateMissingName(t *testing.T) {
	body := `{"md5":"5d41402abc4b2a76b9719d911017c592"}`
	rec := sendRequest(t, NewRouter(newMockThreatRepository()), http.MethodPost, "/info", body)
	assertStatus(t, rec, http.StatusBadRequest)
}

func TestGetInvalidMD5(t *testing.T) {
	rec := sendRequest(t, NewRouter(newMockThreatRepository()), http.MethodGet, "/info/invalid", "")
	assertStatus(t, rec, http.StatusBadRequest)
}

func TestUpdateInvalidMD5(t *testing.T) {
	rec := sendRequest(t, NewRouter(newMockThreatRepository()), http.MethodPut, "/info/invalid", `{"name":"Updated Trojan"}`)
	assertStatus(t, rec, http.StatusBadRequest)
}

func TestUpdateMissingName(t *testing.T) {
	rec := sendRequest(t, NewRouter(newMockThreatRepository()), http.MethodPut, "/info/"+testMD5, `{"severity":"high"}`)
	assertStatus(t, rec, http.StatusBadRequest)
}

func TestCreateUnknownField(t *testing.T) {
	body := `{"md5":"5d41402abc4b2a76b9719d911017c592","name":"Test Trojan","unexpected":"value"}`
	rec := sendRequest(t, NewRouter(newMockThreatRepository()), http.MethodPost, "/info", body)
	assertStatus(t, rec, http.StatusBadRequest)
}

func TestMethodNotAllowed(t *testing.T) {
	rec := sendRequest(t, NewRouter(newMockThreatRepository()), http.MethodDelete, "/info/"+testMD5, "")
	assertStatus(t, rec, http.StatusMethodNotAllowed)
}

func TestCreateThreatInternalError(t *testing.T) {
	repo := newMockThreatRepository()
	repo.err = errors.New("database unavailable")
	body := `{"md5":"5d41402abc4b2a76b9719d911017c592","name":"Test Trojan","threat_type":"trojan","severity":"high"}`
	rec := sendRequest(t, NewRouter(repo), http.MethodPost, "/info", body)
	assertStatus(t, rec, http.StatusInternalServerError)
}

func TestGetThreatInternalError(t *testing.T) {
	repo := newMockThreatRepository()
	repo.err = errors.New("database unavailable")
	rec := sendRequest(t, NewRouter(repo), http.MethodGet, "/info/"+testMD5, "")
	assertStatus(t, rec, http.StatusInternalServerError)
}

func TestUpdateThreatInternalError(t *testing.T) {
	repo := newMockThreatRepository()
	repo.err = errors.New("database unavailable")
	body := `{"name":"Updated Trojan","threat_type":"trojan","severity":"high"}`
	rec := sendRequest(t, NewRouter(repo), http.MethodPut, "/info/"+testMD5, body)
	assertStatus(t, rec, http.StatusInternalServerError)
}
