package main

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/annpolukaro/threat-information-service/internal/handler"
	"github.com/annpolukaro/threat-information-service/internal/repository"
)

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stdout, nil))

	// подключение к PostgreSQL
	databaseURL := os.Getenv("DATABASE_URL")
	if databaseURL == "" {
		logger.Error("DATABASE_URL is not set")
		os.Exit(1)
	}

	// ключ для доступа к POST и PUT
	apiKey := os.Getenv("API_KEY")
	if apiKey == "" {
		logger.Error("API_KEY is not set")
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(
		context.Background(),
		os.Interrupt,
		syscall.SIGTERM,
	)
	defer stop()

	// подключение к базе данных
	pool, err := repository.Connect(ctx, databaseURL)
	if err != nil {
		logger.Error("failed to connect to database", "error", err)
		os.Exit(1)
	}
	defer pool.Close()

	// создание репозитория и HTTP-маршрутизатора
	repo := repository.NewThreatRepository(pool)
	router := handler.NewRouter(repo, apiKey)

	// настройка HTTP-сервера
	server := &http.Server{
		Addr:              ":8080",
		Handler:           router,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	serverErrors := make(chan error, 1)

	// запуск HTTP-сервера
	go func() {
		logger.Info("HTTP server started", "address", server.Addr)

		err := server.ListenAndServe()
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			serverErrors <- err
		}
	}()

	// ожидание сигнала завершения или ошибки сервера
	select {
	case <-ctx.Done():
		logger.Info("shutdown signal received")

	case err := <-serverErrors:
		logger.Error("HTTP server failed", "error", err)
		stop()
	}

	// корректное завершение сервера
	shutdownCtx, cancel := context.WithTimeout(
		context.Background(),
		10*time.Second,
	)
	defer cancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		logger.Error("failed to shutdown server", "error", err)
	}

	logger.Info("server stopped")
}
