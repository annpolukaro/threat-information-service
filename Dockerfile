
# сборка Go-приложения
FROM golang:1.26-alpine AS builder

WORKDIR /app

# копируем файлы зависимостей
COPY go.mod go.sum ./

# загружаем зависимости
RUN go mod download

# копируем исходный код
COPY . .

# собираем статический бинарный файл
RUN CGO_ENABLED=0 GOOS=linux go build \
    -trimpath \
    -ldflags="-s -w" \
    -o /app/server ./cmd/server


# минимальный образ для запуска
FROM alpine:3.22

# устанавливаем корневые сертификаты
RUN apk add --no-cache ca-certificates

# создаём непривилегированного пользователя
RUN addgroup -S appgroup && \
    adduser -S -G appgroup appuser

WORKDIR /app

# копируем исполняемый файл
COPY --from=builder --chown=appuser:appgroup \
    /app/server /app/server

# запускаем приложение без root-прав
USER appuser


EXPOSE 8080

# Запуск сервера
CMD ["/app/server"]
