# Threat Information Service

REST API-сервис для хранения информации о компьютерных угрозах по MD5-хешу файла. Написан на Go с использованием PostgreSQL. HTTP-интерфейс реализован на основе [OpenAPI-спецификации](api/openapi.yaml) из задания.

## Возможности

- Создание, получение и обновление информации об угрозах.
- Валидация входных данных и обработка ошибок.
- Авторизация по API-ключу для POST и PUT.
- Ограничение частоты запросов (rate limiting).
- HTTPS через Nginx.
- Модульные и интеграционные тесты.

## Стек

- Go
- PostgreSQL 17
- Docker Compose
- Nginx
- OpenAPI 3.0

## Модель угрозы

К исходным полям `md5` и `name` добавлены:

- `description` — описание угрозы.
- `threat_type` — тип угрозы.
- `severity` — уровень опасности.
- `first_seen_at` — дата первого обнаружения.
- `created_at` — дата создания записи.
- `updated_at` — дата обновления записи.

Для `threat_type` предусмотрены значения `trojan`, `virus`, `worm`, `ransomware`, `spyware`, `other`. Для `severity` — `low`, `medium`, `high`, `critical`.

MD5 проверяется на соответствие формату из 32 шестнадцатеричных символов. Название угрозы обязательно, максимальная длина — 255 символов.

## Запуск

Для запуска нужны Docker и Docker Compose. Команды ниже приведены для Windows PowerShell.

**1. Создать `.env` из шаблона:**

```powershell
Copy-Item .env.example .env
```

В `.env` необходимо задать пароль PostgreSQL и `API_KEY`.

**2. Создать сертификат для HTTPS:**

```powershell
New-Item -ItemType Directory -Force certs | Out-Null

docker run --rm `
  -v "${PWD}:/work" `
  -w /work `
  alpine/openssl req -x509 -nodes -newkey rsa:2048 `
  -keyout certs/server.key `
  -out certs/server.crt `
  -days 365 `
  -subj "/CN=localhost" `
  -addext "subjectAltName=DNS:localhost"
```

Сертификат самоподписанный и предназначен для локального запуска.

**3. Запустить сервис:**

```powershell
docker compose up --build -d
```

**4. Проверить доступность:**

```powershell
curl.exe -k https://localhost/healthz
```

Ожидаемый ответ:

```json
{"status":"ok"}
```

Сервис доступен по адресу `https://localhost`. Флаг `-k` нужен для работы с локальным самоподписанным сертификатом.

Остановить контейнеры:

```powershell
docker compose down
```

## API

| Метод | Endpoint | Описание |
|---|---|---|
| POST | `/info` | Создание записи об угрозе |
| GET | `/info/{md5}` | Получение информации по MD5 |
| PUT | `/info/{md5}` | Обновление существующей записи |

Для POST и PUT требуется заголовок `X-API-Key` со значением из `.env`.

Пример создания записи:

```json
{
  "md5": "5d41402abc4b2a76b9719d911017c592",
  "name": "Trojan.Win32.Generic",
  "description": "Вредоносная программа",
  "threat_type": "trojan",
  "severity": "high",
  "first_seen_at": "2026-01-15T10:30:00Z"
}
```

Подробное описание запросов, ответов и HTTP-статусов находится в [`api/openapi.yaml`](api/openapi.yaml).

## Защита

- **HTTPS** — Nginx принимает HTTPS-запросы и перенаправляет HTTP на HTTPS.
- **API-ключ** — операции создания и обновления требуют авторизации.
- **Rate limiting** — 10 запросов в секунду на IP с `burst = 20`.
- **Валидация** — проверка полей, ограничение размера JSON до 1 МиБ и отклонение неизвестных полей.
- **Доверенный прокси** — клиентский IP из `X-Real-IP` принимается только от доверенного Nginx.

Настройки Docker Compose рассчитаны на локальное тестирование.

## Тесты

Запуск всех тестов:

```powershell
go test -count=1 ./...
```

В проекте есть unit-тесты модели и HTTP-обработчиков, а также интеграционные тесты репозитория с PostgreSQL.

Для запуска интеграционных тестов необходимо поднять PostgreSQL и задать `DATABASE_URL`. Если переменная не задана, эти тесты пропускаются.

```powershell
docker compose up -d postgres

$env:DATABASE_URL = "postgres://threat_user:ВАШ_ПАРОЛЬ@localhost:15432/threats_db?sslmode=disable"

go test -count=1 -v ./internal/repository/...
```

Параметры подключения нужно взять из своего `.env`. Интеграционные тесты следует выполнять на отдельной тестовой базе.

## Структура проекта

```text
api/                 OpenAPI-спецификация
cmd/server/          Точка входа приложения
internal/domain/     Модель угрозы и валидация
internal/handler/    HTTP-обработчики и middleware
internal/repository/ Работа с PostgreSQL
migrations/          SQL-скрипт создания таблицы
nginx/               Конфигурация Nginx
```
