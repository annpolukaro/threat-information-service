package handler

import (
	"net/http"

	"github.com/annpolukaro/threat-information-service/internal/api/generated"
)

type GeneratedAdapter struct {
	handler *ThreatHandler
}

var _ generated.ServerInterface = (*GeneratedAdapter)(nil)

func NewGeneratedAdapter(h *ThreatHandler) *GeneratedAdapter {
	return &GeneratedAdapter{handler: h}
}

func (a *GeneratedAdapter) CreateThreat(
	w http.ResponseWriter,
	r *http.Request,
) {
	a.handler.Create(w, r)
}

func (a *GeneratedAdapter) GetInfoByMd5(
	w http.ResponseWriter,
	r *http.Request,
	md5 string,
) {
	r.SetPathValue("md5", md5)
	a.handler.GetByMD5(w, r)
}

func (a *GeneratedAdapter) UpdateInfoByMd5(
	w http.ResponseWriter,
	r *http.Request,
	md5 string,
) {
	r.SetPathValue("md5", md5)
	a.handler.Update(w, r)
}
