package repository

import (
	"context"
	"os"
	"testing"
)

func TestConnect(t *testing.T) {
	databaseURL := os.Getenv("DATABASE_URL")

	if databaseURL == "" {
		t.Skip("DATABASE_URL is not set")
	}

	pool, err := Connect(context.Background(), databaseURL)
	if err != nil {
		t.Fatalf("failed to connect to database: %v", err)
	}
	defer pool.Close()

	var result int

	err = pool.QueryRow(
		context.Background(),
		"SELECT 1",
	).Scan(&result)

	if err != nil {
		t.Fatalf("query failed: %v", err)
	}

	if result != 1 {
		t.Fatalf("expected 1, got %d", result)
	}
}
