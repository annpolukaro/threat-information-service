package repository

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/annpolukaro/threat-information-service/internal/domain"
)

func TestCreateThreat(t *testing.T) {
	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		t.Skip("DATABASE_URL is not set")
	}

	ctx := context.Background()

	pool, err := Connect(ctx, databaseURL)
	if err != nil {
		t.Fatalf("connect to database: %v", err)
	}

	t.Cleanup(func() {
		pool.Close()
	})

	repo := NewThreatRepository(pool)

	threat := &domain.Threat{
		MD5:         "5d41402abc4b2a76b9719d911017c592",
		Name:        "Test Trojan",
		Description: "Test threat",
		ThreatType:  domain.ThreatType("trojan"),
		Severity:    domain.Severity("high"),
	}

	// Удаляем старую тестовую запись.
	_, err = pool.Exec(ctx,
		"DELETE FROM threats WHERE md5 = $1",
		threat.MD5,
	)
	if err != nil {
		t.Fatalf("cleanup before test: %v", err)
	}

	// Удаляем тестовую запись после завершения теста.
	t.Cleanup(func() {
		_, err := pool.Exec(
			context.Background(),
			"DELETE FROM threats WHERE md5 = $1",
			threat.MD5,
		)
		if err != nil {
			t.Errorf("cleanup after test: %v", err)
		}
	})

	// Проверяем создание угрозы.
	err = repo.Create(ctx, threat)
	if err != nil {
		t.Fatalf("create threat: %v", err)
	}

	// Проверяем, что PostgreSQL установил дату создания.
	if threat.CreatedAt.IsZero() {
		t.Fatal("created_at was not set")
	}

	// Проверяем, что угроза сохранилась в базе.
	var name string

	err = pool.QueryRow(
		ctx,
		"SELECT name FROM threats WHERE md5 = $1",
		threat.MD5,
	).Scan(&name)

	if err != nil {
		t.Fatalf("select threat: %v", err)
	}

	if name != threat.Name {
		t.Fatalf("expected name %q, got %q", threat.Name, name)
	}

	// Проверяем ошибку при повторном создании угрозы.
	err = repo.Create(ctx, threat)
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("expected ErrConflict, got %v", err)
	}
}

func TestGetByMD5(t *testing.T) {
	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		t.Skip("DATABASE_URL is not set")
	}

	ctx := context.Background()

	pool, err := Connect(ctx, databaseURL)
	if err != nil {
		t.Fatalf("connect to database: %v", err)
	}

	t.Cleanup(func() {
		pool.Close()
	})

	repo := NewThreatRepository(pool)

	threat := &domain.Threat{
		MD5:         "098f6bcd4621d373cade4e832627b4f6",
		Name:        "Test Virus",
		Description: "Virus for testing GetByMD5",
		ThreatType:  domain.ThreatType("virus"),
		Severity:    domain.Severity("medium"),
	}

	// Удаляем запись, если она осталась после прошлого запуска.
	_, err = pool.Exec(
		ctx,
		"DELETE FROM threats WHERE md5 = $1",
		threat.MD5,
	)
	if err != nil {
		t.Fatalf("cleanup before test: %v", err)
	}

	// Регистрируем удаление записи после теста.
	t.Cleanup(func() {
		_, err := pool.Exec(
			context.Background(),
			"DELETE FROM threats WHERE md5 = $1",
			threat.MD5,
		)
		if err != nil {
			t.Errorf("cleanup after test: %v", err)
		}
	})

	// Создаём угрозу в PostgreSQL.
	err = repo.Create(ctx, threat)
	if err != nil {
		t.Fatalf("create threat: %v", err)
	}

	// Получаем угрозу по MD5.
	foundThreat, err := repo.GetByMD5(ctx, threat.MD5)
	if err != nil {
		t.Fatalf("get threat by md5: %v", err)
	}

	// Проверяем, что вернулась нужная угроза.
	if foundThreat.MD5 != threat.MD5 {
		t.Errorf(
			"expected MD5 %q, got %q",
			threat.MD5,
			foundThreat.MD5,
		)
	}

	if foundThreat.Name != threat.Name {
		t.Errorf(
			"expected name %q, got %q",
			threat.Name,
			foundThreat.Name,
		)
	}

	if foundThreat.Severity != threat.Severity {
		t.Errorf(
			"expected severity %q, got %q",
			threat.Severity,
			foundThreat.Severity,
		)
	}

	// Проверяем поиск несуществующей угрозы.
	_, err = repo.GetByMD5(
		ctx,
		"00000000000000000000000000000000",
	)

	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestUpdateThreat(t *testing.T) {
	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		t.Skip("DATABASE_URL is not set")
	}

	ctx := context.Background()

	pool, err := Connect(ctx, databaseURL)
	if err != nil {
		t.Fatalf("connect to database: %v", err)
	}

	t.Cleanup(func() {
		pool.Close()
	})

	repo := NewThreatRepository(pool)

	threat := &domain.Threat{
		MD5:         "e99a18c428cb38d5f260853678922e03",
		Name:        "Original Virus",
		Description: "Original description",
		ThreatType:  domain.ThreatType("virus"),
		Severity:    domain.Severity("low"),
	}

	// Удаляем возможную старую тестовую запись.
	_, err = pool.Exec(
		ctx,
		"DELETE FROM threats WHERE md5 = $1",
		threat.MD5,
	)
	if err != nil {
		t.Fatalf("cleanup before test: %v", err)
	}

	t.Cleanup(func() {
		_, err := pool.Exec(
			context.Background(),
			"DELETE FROM threats WHERE md5 = $1",
			threat.MD5,
		)
		if err != nil {
			t.Errorf("cleanup after test: %v", err)
		}
	})

	// Создаём угрозу.
	if err := repo.Create(ctx, threat); err != nil {
		t.Fatalf("create threat: %v", err)
	}

	// Изменяем информацию.
	threat.Name = "Updated Virus"
	threat.Description = "Updated description"
	threat.Severity = domain.Severity("critical")

	// Сохраняем изменения.
	if err := repo.Update(ctx, threat); err != nil {
		t.Fatalf("update threat: %v", err)
	}

	// Читаем запись заново из PostgreSQL.
	updated, err := repo.GetByMD5(ctx, threat.MD5)
	if err != nil {
		t.Fatalf("get updated threat: %v", err)
	}

	if updated.Name != "Updated Virus" {
		t.Errorf("unexpected name: %s", updated.Name)
	}

	if updated.Description != "Updated description" {
		t.Errorf("unexpected description: %s", updated.Description)
	}

	if updated.Severity != domain.Severity("critical") {
		t.Errorf("unexpected severity: %s", updated.Severity)
	}

	// Проверяем обновление несуществующей угрозы.
	missing := &domain.Threat{
		MD5:        "00000000000000000000000000000000",
		Name:       "Missing Threat",
		ThreatType: domain.ThreatType("other"),
		Severity:   domain.Severity("medium"),
	}

	err = repo.Update(ctx, missing)
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
}

func TestThreatFirstSeenAt(t *testing.T) {
	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		t.Skip("DATABASE_URL is not set")
	}

	ctx := context.Background()

	pool, err := Connect(ctx, databaseURL)
	if err != nil {
		t.Fatalf("connect to database: %v", err)
	}

	t.Cleanup(func() {
		pool.Close()
	})

	repo := NewThreatRepository(pool)

	md5 := "098f6bcd4621d373cade4e832627b4f6"

	// Удаляем тестовую запись перед запуском.
	_, err = pool.Exec(ctx, "DELETE FROM threats WHERE md5 = $1", md5)
	if err != nil {
		t.Fatalf("cleanup before test: %v", err)
	}

	// Удаляем запись после теста.
	t.Cleanup(func() {
		_, err := pool.Exec(
			context.Background(),
			"DELETE FROM threats WHERE md5 = $1",
			md5,
		)
		if err != nil {
			t.Errorf("cleanup after test: %v", err)
		}
	})

	firstSeen := time.Date(
		2024, 1, 15, 10, 30, 0, 0, time.UTC,
	)

	threat := &domain.Threat{
		MD5:         md5,
		Name:        "Test Trojan",
		Description: "Test first_seen_at",
		ThreatType:  domain.ThreatTypeTrojan,
		Severity:    domain.SeverityHigh,
		FirstSeenAt: &firstSeen,
	}

	// 1. Создаём угрозу.
	if err := repo.Create(ctx, threat); err != nil {
		t.Fatalf("create threat: %v", err)
	}

	// 2. Читаем её из PostgreSQL.
	saved, err := repo.GetByMD5(ctx, md5)
	if err != nil {
		t.Fatalf("get threat: %v", err)
	}

	if saved.FirstSeenAt == nil {
		t.Fatal("first_seen_at is nil after create")
	}

	if !saved.FirstSeenAt.Equal(firstSeen) {
		t.Errorf(
			"expected first_seen_at %v, got %v",
			firstSeen,
			*saved.FirstSeenAt,
		)
	}

	// 3. Меняем дату первого обнаружения.
	updatedFirstSeen := time.Date(
		2025, 3, 20, 14, 0, 0, 0, time.UTC,
	)

	saved.FirstSeenAt = &updatedFirstSeen

	if err := repo.Update(ctx, saved); err != nil {
		t.Fatalf("update threat: %v", err)
	}

	// 4. Повторно читаем запись из PostgreSQL.
	updated, err := repo.GetByMD5(ctx, md5)
	if err != nil {
		t.Fatalf("get updated threat: %v", err)
	}

	if updated.FirstSeenAt == nil {
		t.Fatal("first_seen_at is nil after update")
	}

	if !updated.FirstSeenAt.Equal(updatedFirstSeen) {
		t.Errorf(
			"expected updated first_seen_at %v, got %v",
			updatedFirstSeen,
			*updated.FirstSeenAt,
		)
	}
}
