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

type ThreatRepository interface {
	Create(ctx context.Context, threat *domain.Threat) error
	GetByMD5(ctx context.Context, md5 string) (*domain.Threat, error)
	Update(ctx context.Context, threat *domain.Threat) error
}

type ThreatHandler struct {
	repo ThreatRepository
}

func NewThreatHandler(repo ThreatRepository) *ThreatHandler {
	return &ThreatHandler{repo: repo}
}

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

	if err := decoder.Decode(dst); err != nil {
		return err
	}

	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return errors.New("request body must contain a single JSON object")
		}
		return err
	}

	return nil
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

	if err := threat.Validate(); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid threat data", err.Error())
		return
	}

	if err := h.repo.Create(r.Context(), &threat); err != nil {
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

	if !domain.ValidateMD5(md5) {
		writeError(w, http.StatusBadRequest, "Invalid MD5", "")
		return
	}

	threat, err := h.repo.GetByMD5(r.Context(), strings.ToLower(md5))
	if err != nil {
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

	if !domain.ValidateMD5(md5) {
		writeError(w, http.StatusBadRequest, "Invalid MD5", "")
		return
	}

	var req updateThreatRequest

	if err := decodeJSON(w, r, &req); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid request body", err.Error())
		return
	}

	threat := domain.Threat{
		MD5:         strings.ToLower(md5),
		Name:        req.Name,
		Description: req.Description,
		ThreatType:  req.ThreatType,
		Severity:    req.Severity,
		FirstSeenAt: req.FirstSeenAt,
	}

	if err := threat.Validate(); err != nil {
		writeError(w, http.StatusBadRequest, "Invalid threat data", err.Error())
		return
	}

	if err := h.repo.Update(r.Context(), &threat); err != nil {
		if errors.Is(err, repository.ErrNotFound) {
			writeError(w, http.StatusNotFound, "Threat not found", "")
			return
		}

		writeError(w, http.StatusInternalServerError, "Internal server error", "")
		return
	}

	writeJSON(w, http.StatusOK, threat)
}
