package repository

import (
	"context"
	"errors"
	"fmt"

	"github.com/annpolukaro/threat-information-service/internal/domain"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

var (
	ErrNotFound = errors.New("threat not found")
	ErrConflict = errors.New("threat already exists")
)

type ThreatRepository struct {
	pool *pgxpool.Pool
}

func NewThreatRepository(pool *pgxpool.Pool) *ThreatRepository {
	return &ThreatRepository{pool: pool}
}

func (r *ThreatRepository) Create(ctx context.Context, threat *domain.Threat) error {
	query := `
		INSERT INTO threats (
			md5,
			name,
			description,
			threat_type,
			severity,
			first_seen_at
		)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING created_at, updated_at
	`

	err := r.pool.QueryRow(
		ctx,
		query,
		threat.MD5,
		threat.Name,
		threat.Description,
		threat.ThreatType,
		threat.Severity,
		threat.FirstSeenAt,
	).Scan(&threat.CreatedAt, &threat.UpdatedAt)

	if err != nil {
		var pgErr *pgconn.PgError

		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return ErrConflict
		}

		return fmt.Errorf("create threat: %w", err)
	}

	return nil
}

func (r *ThreatRepository) GetByMD5(
	ctx context.Context,
	md5 string,
) (*domain.Threat, error) {
	query := `
		SELECT
			md5,
			name,
			description,
			threat_type,
			severity,
			first_seen_at,
			created_at,
			updated_at
		FROM threats
		WHERE md5 = $1
	`

	var threat domain.Threat

	err := r.pool.QueryRow(ctx, query, md5).Scan(
		&threat.MD5,
		&threat.Name,
		&threat.Description,
		&threat.ThreatType,
		&threat.Severity,
		&threat.FirstSeenAt,
		&threat.CreatedAt,
		&threat.UpdatedAt,
	)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, ErrNotFound
		}

		return nil, fmt.Errorf("get threat by md5: %w", err)
	}

	return &threat, nil
}

func (r *ThreatRepository) Update(
	ctx context.Context,
	threat *domain.Threat,
) error {
	query := `
		UPDATE threats
		SET
			name = $2,
			description = $3,
			threat_type = $4,
			severity = $5,
			first_seen_at = $6,
			updated_at = NOW()
		WHERE md5 = $1
		RETURNING created_at, updated_at
	`

	err := r.pool.QueryRow(
		ctx,
		query,
		threat.MD5,
		threat.Name,
		threat.Description,
		threat.ThreatType,
		threat.Severity,
		threat.FirstSeenAt,
	).Scan(
		&threat.CreatedAt,
		&threat.UpdatedAt,
	)

	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}

		return fmt.Errorf("update threat: %w", err)
	}

	return nil
}
