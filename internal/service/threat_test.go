package service

import (
	"context"
	"errors"
	"testing"

	"github.com/annpolukaro/threat-information-service/internal/domain"
	"github.com/annpolukaro/threat-information-service/internal/repository"
)

type fakeRepository struct {
	saved        *domain.Threat
	requestedMD5 string
	err          error
}

func (f *fakeRepository) Create(_ context.Context, t *domain.Threat) error {
	if f.err != nil {
		return f.err
	}
	f.saved = t
	return nil
}
func (f *fakeRepository) GetByMD5(_ context.Context, md5 string) (*domain.Threat, error) {
	f.requestedMD5 = md5
	if f.err != nil {
		return nil, f.err
	}
	return f.saved, nil
}
func (f *fakeRepository) Update(_ context.Context, t *domain.Threat) error {
	if f.err != nil {
		return f.err
	}
	f.saved = t
	return nil
}

func TestCreateValidatesAndNormalizes(t *testing.T) {
	repo := &fakeRepository{}
	svc := NewThreatService(repo)
	threat := &domain.Threat{MD5: "5D41402ABC4B2A76B9719D911017C592", Name: "  Trojan  "}
	if err := svc.Create(context.Background(), threat); err != nil {
		t.Fatal(err)
	}
	if repo.saved == nil || threat.MD5 != "5d41402abc4b2a76b9719d911017c592" || threat.Name != "Trojan" || threat.Severity != domain.SeverityMedium || threat.ThreatType != domain.ThreatTypeOther {
		t.Fatalf("unexpected threat: %+v", threat)
	}
}
func TestCreateRejectsInvalidThreat(t *testing.T) {
	repo := &fakeRepository{}
	err := NewThreatService(repo).Create(context.Background(), &domain.Threat{MD5: "invalid", Name: "Trojan"})
	if !errors.Is(err, domain.ErrInvalidMD5) || repo.saved != nil {
		t.Fatalf("unexpected result: %v", err)
	}
}
func TestGetNormalizesMD5(t *testing.T) {
	repo := &fakeRepository{saved: &domain.Threat{Name: "Trojan"}}
	_, err := NewThreatService(repo).GetByMD5(context.Background(), "5D41402ABC4B2A76B9719D911017C592")
	if err != nil || repo.requestedMD5 != "5d41402abc4b2a76b9719d911017c592" {
		t.Fatalf("unexpected result: %v, %s", err, repo.requestedMD5)
	}
}
func TestUpdateValidatesAndPreservesErrors(t *testing.T) {
	repo := &fakeRepository{err: repository.ErrNotFound}
	svc := NewThreatService(repo)
	err := svc.Update(context.Background(), &domain.Threat{MD5: "5d41402abc4b2a76b9719d911017c592", Name: "Trojan"})
	if !errors.Is(err, repository.ErrNotFound) {
		t.Fatalf("unexpected error: %v", err)
	}
}
func TestGetRejectsInvalidMD5(t *testing.T) {
	_, err := NewThreatService(&fakeRepository{}).GetByMD5(context.Background(), "invalid")
	if !errors.Is(err, domain.ErrInvalidMD5) {
		t.Fatalf("unexpected error: %v", err)
	}
}
