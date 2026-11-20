package handler

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/annpolukaro/threat-information-service/internal/domain"
	"github.com/annpolukaro/threat-information-service/internal/repository"
)

type ThreatService interface {
	Create(context.Context, *domain.Threat) error
	GetByMD5(context.Context, string) (*domain.Threat, error)
	Update(context.Context, *domain.Threat) error
}

type ThreatHandler struct{ service ThreatService }

func NewThreatHandler(svc ThreatService) *ThreatHandler { return &ThreatHandler{service: svc} }

type createThreatRequest struct {
	MD5         string            `json:"md5"`
	Name        string            `json:"name"`
	Description string            `json:"description"`
	ThreatType  domain.ThreatType `json:"threat_type"`
	Severity    domain.Severity   `json:"severity"`
	FirstSeenAt *time.Time        `json:"first_seen_at"`
}

type updateThreatRequest struct {
	Name        string            `json:"name"`
	Description string            `json:"description"`
	ThreatType  domain.ThreatType `json:"threat_type"`
	Severity    domain.Severity   `json:"severity"`
	FirstSeenAt *time.Time        `json:"first_seen_at"`
}

type errorResponse struct {
	Message string `json:"message"`
	Details string `json:"details,omitempty"`
}

func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)

	_ = json.NewEncoder(w).Encode(data)
}

func writeError(w http.ResponseWriter, status int, message, details string) {
	writeJSON(w, status, errorResponse{
		Message: message,
		Details: details,
	})
}

const maxBodySize = 1 << 20

func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) error {
	r.Body = http.MaxBytesReader(w, r.Body, maxBodySize)

	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()

	var raw json.RawMessage
	if err := decoder.Decode(&raw); err != nil {
		return err
	}

	// верхнеуровневое значение должно быть JSON-объектом.
	trimmed := strings.TrimSpace(string(raw))
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return errors.New("request body must be a JSON object")
	}

	// проверяем, что в теле находится только одно JSON-значение
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return errors.New("request body must contain a single JSON object")
		}
		return err
	}

	// декодируем объект в структуру запроса.
	strictDecoder := json.NewDecoder(strings.NewReader(trimmed))
	strictDecoder.DisallowUnknownFields()

	return strictDecoder.Decode(dst)
}

func (h *ThreatHandler) Create(w http.ResponseWriter, r *http.Request) {
	var req createThreatRequest

	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}

	threat := domain.Threat{
		MD5:         req.MD5,
		Name:        req.Name,
		Description: req.Description,
		ThreatType:  req.ThreatType,
		Severity:    req.Severity,
		FirstSeenAt: req.FirstSeenAt,
	}

	if err := h.service.Create(r.Context(), &threat); err != nil {
		if isInvalidThreat(err) {
			writeError(w, http.StatusBadRequest, "Invalid threat data", err.Error())
			return
		}
		if errors.Is(err, repository.ErrConflict) {
			writeError(w, http.StatusConflict, "Threat already exists", "")
			return
		}

		writeError(w, http.StatusInternalServerError, "Internal server error", "")
		return
	}

	writeJSON(w, http.StatusCreated, threat)
}

func (h *ThreatHandler) GetByMD5(w http.ResponseWriter, r *http.Request) {
	md5 := r.PathValue("md5")

	threat, err := h.service.GetByMD5(r.Context(), md5)
	if err != nil {
		if errors.Is(err, domain.ErrInvalidMD5) {
			writeError(w, http.StatusBadRequest, "Invalid MD5", "")
			return
		}
		if errors.Is(err, repository.ErrNotFound) {
			writeError(w, http.StatusNotFound, "Threat not found", "")
			return
		}

		writeError(w, http.StatusInternalServerError, "Internal server error", "")
		return
	}

	writeJSON(w, http.StatusOK, threat)
}

func (h *ThreatHandler) Update(w http.ResponseWriter, r *http.Request) {
	md5 := r.PathValue("md5")

	var req updateThreatRequest

	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}

	threat := domain.Threat{
		MD5:         md5,
		Name:        req.Name,
		Description: req.Description,
		ThreatType:  req.ThreatType,
		Severity:    req.Severity,
		FirstSeenAt: req.FirstSeenAt,
	}

	if err := h.service.Update(r.Context(), &threat); err != nil {
		if errors.Is(err, domain.ErrInvalidMD5) {
			writeError(w, http.StatusBadRequest, "Invalid MD5", "")
			return
		}
		if isInvalidThreat(err) {
			writeError(w, http.StatusBadRequest, "Invalid threat data", err.Error())
			return
		}
		if errors.Is(err, repository.ErrNotFound) {
			writeError(w, http.StatusNotFound, "Threat not found", "")
			return
		}

		writeError(w, http.StatusInternalServerError, "Internal server error", "")
		return
	}

	writeJSON(w, http.StatusOK, threat)
}

// isInvalidThreat identifies validation errors returned by the domain model.
func isInvalidThreat(err error) bool {
	return errors.Is(err, domain.ErrInvalidMD5) || errors.Is(err, domain.ErrInvalidName) ||
		errors.Is(err, domain.ErrInvalidThreatType) || errors.Is(err, domain.ErrInvalidSeverity)
}
