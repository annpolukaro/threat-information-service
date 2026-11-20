package service

import (
	"context"
	"fmt"
	"strings"

	"github.com/annpolukaro/threat-information-service/internal/domain"
)

// ThreatRepository defines the persistence operations required by ThreatService.
type ThreatRepository interface {
	Create(context.Context, *domain.Threat) error
	GetByMD5(context.Context, string) (*domain.Threat, error)
	Update(context.Context, *domain.Threat) error
}

// ThreatService coordinates threat business operations independently of HTTP.
type ThreatService struct{ repo ThreatRepository }

func NewThreatService(repo ThreatRepository) *ThreatService { return &ThreatService{repo: repo} }

func (s *ThreatService) Create(ctx context.Context, threat *domain.Threat) error {
	if err := threat.Validate(); err != nil {
		return err
	}
	if err := s.repo.Create(ctx, threat); err != nil {
		return fmt.Errorf("create threat: %w", err)
	}
	return nil
}

func (s *ThreatService) GetByMD5(ctx context.Context, md5 string) (*domain.Threat, error) {
	if !domain.ValidateMD5(md5) {
		return nil, domain.ErrInvalidMD5
	}
	threat, err := s.repo.GetByMD5(ctx, strings.ToLower(md5))
	if err != nil {
		return nil, fmt.Errorf("get threat: %w", err)
	}
	return threat, nil
}

func (s *ThreatService) Update(ctx context.Context, threat *domain.Threat) error {
	if err := threat.Validate(); err != nil {
		return err
	}
	if err := s.repo.Update(ctx, threat); err != nil {
		return fmt.Errorf("update threat: %w", err)
	}
	return nil
}
