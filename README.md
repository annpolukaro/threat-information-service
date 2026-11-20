# Threat Information Service

REST API-сервис для хранения и получения информации о компьютерных угрозах по MD5-хешу файла. Написан на Go с использованием PostgreSQL. HTTP-интерфейс реализован на основе [OpenAPI-спецификации](api/openapi.yaml).

## Возможности

Сервис поддерживает создание, получение и обновление записей об угрозах. Каждая запись идентифицируется по MD5-хешу файла, который должен быть уникальным.

Перед сохранением данные проходят валидацию. Для создания и обновления записей используется авторизация по API-ключу. Дополнительно реализованы HTTPS, ограничение частоты запросов и обработка ошибок.

В проекте также предусмотрены модульные и интеграционные тесты.

## Технологии

- **Go** — HTTP-сервер и бизнес-логика.
- **PostgreSQL 17** — хранение информации об угрозах.
- **Docker и Docker Compose** — сборка и запуск сервисов.
- **Nginx** — обратное проксирование и HTTPS.
- **OpenAPI 3.0** — описание HTTP-интерфейса и моделей данных.
- **oapi-codegen** — генерация Go-моделей и HTTP-интерфейса по OpenAPI-спецификации.

## Архитектура

Приложение разделено на несколько слоёв:

- **Handler (`internal/handler`)** — обработка HTTP-запросов, формирование ответов и middleware.
- **Service (`internal/service`)** — бизнес-логика, валидация и нормализация данных.
- **Repository (`internal/repository`)** — выполнение SQL-запросов и взаимодействие с PostgreSQL.
- **Domain (`internal/domain`)** — модель угрозы, допустимые значения полей и правила проверки.

Зависимости создаются в `cmd/server/main.go` в порядке `repository → service → handler`.

HTTP-маршруты регистрируются с использованием кода, сгенерированного из OpenAPI-спецификации. Адаптер `internal/handler/generated_adapter.go` связывает сгенерированный интерфейс с существующими обработчиками приложения.

Бизнес-логика и работа с базой данных не зависят от сгенерированного кода.

## Модель угрозы

Модель содержит следующие поля:

| Поле | Описание |
|---|---|
| `md5` | Уникальный MD5-хеш файла, 32 шестнадцатеричных символа |
| `name` | Название угрозы, обязательное поле, не более 255 символов |
| `description` | Дополнительное описание угрозы |
| `threat_type` | Тип угрозы |
| `severity` | Уровень опасности |
| `first_seen_at` | Дата и время первого обнаружения |
| `created_at` | Дата и время создания записи |
| `updated_at` | Дата и время последнего обновления |

Допустимые значения `threat_type`:

`trojan`, `virus`, `worm`, `ransomware`, `spyware`, `other`.

Допустимые значения `severity`:

`low`, `medium`, `high`, `critical`.

Если тип угрозы не указан, используется `other`, а для уровня опасности — `medium`.

MD5 приводится к нижнему регистру, пробелы по краям названия удаляются. Даты передаются в формате RFC 3339.

## Запуск проекта

Для запуска необходимы Docker с поддержкой Compose и свободные порты `80`, `443` и `15432` (при использовании стандартной конфигурации).

Команды ниже приведены для Windows PowerShell и выполняются из корня проекта.

### 1. Настройка окружения

Создайте `.env` на основе `.env.example`:

```powershell
Copy-Item .env.example .env
```

Укажите необходимые переменные:

```dotenv
POSTGRES_USER=threat_user
POSTGRES_PASSWORD=replace_with_your_db_password
POSTGRES_DB=threats_db
POSTGRES_PORT=15432

API_KEY=replace_with_your_long_random_api_key
```

Замените пароль PostgreSQL и API-ключ на собственные значения.

Файл `.env` содержит локальные настройки и не должен добавляться в Git.

### 2. Создание TLS-сертификата

Для HTTPS необходимы файлы:

- `certs/server.crt` — сертификат.
- `certs/server.key` — приватный ключ.

Для локального запуска можно создать самоподписанный сертификат:

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

Если сертификат уже создан, повторять этот шаг не требуется.

Самоподписанный сертификат предназначен только для локального тестирования. Приватный ключ не должен попадать в репозиторий.

### 3. Запуск контейнеров

```powershell
docker compose up --build -d
```

Проверить состояние сервисов:

```powershell
docker compose ps
```

Docker Compose запускает PostgreSQL, Go-приложение и Nginx.

Для просмотра логов:

```powershell
docker compose logs --tail=100 postgres api nginx
```

### 4. Проверка работы

После запуска проверьте endpoint состояния сервиса:

```powershell
curl.exe -k -i https://localhost/healthz
```

Ожидаемый HTTP-статус — `200 OK`, тело ответа:

```json
{"status":"ok"}
```

Параметр `-k` используется для работы с локальным самоподписанным сертификатом.

Для остановки контейнеров:

```powershell
docker compose down
```

Данные PostgreSQL при этом сохраняются. Команда `docker compose down -v` дополнительно удаляет тома, включая данные базы.

## API

Полная спецификация доступна в [api/openapi.yaml](api/openapi.yaml).

Для запросов POST и PUT необходим заголовок `X-API-Key`. GET-запросы доступны без API-ключа.

В PowerShell можно заранее определить переменные:

```powershell
$apiKey = "ВАШ_API_KEY_ИЗ_ENV"
$md5 = "5d41402abc4b2a76b9719d911017c592"
```

### POST `/info`

Создание новой записи об угрозе.

Пример файла `create.json`:

```json
{
  "md5": "5d41402abc4b2a76b9719d911017c592",
  "name": "Trojan.Win32.Generic",
  "description": "Тестовая запись об угрозе",
  "threat_type": "trojan",
  "severity": "high",
  "first_seen_at": "2026-01-15T10:30:00Z"
}
```

Запрос:

```powershell
curl.exe -k -i -X POST https://localhost/info `
  -H "Content-Type: application/json" `
  -H "X-API-Key: $apiKey" `
  --data-binary "@create.json"
```

При успешном создании возвращается `201 Created`.

Если запись с таким MD5 уже существует, возвращается `409 Conflict`.

### GET `/info/{md5}`

Получение информации об угрозе по MD5:

```powershell
curl.exe -k -i "https://localhost/info/$md5"
```

Возможные ответы:

- `200 OK` — запись найдена.
- `400 Bad Request` — неверный формат MD5.
- `404 Not Found` — запись не найдена.

### PUT `/info/{md5}`

Обновление существующей записи. MD5 указывается в URL и не изменяется.

Пример файла `update.json`:

```json
{
  "name": "Trojan.Win32.Updated",
  "description": "Обновлённое описание угрозы",
  "threat_type": "trojan",
  "severity": "critical",
  "first_seen_at": "2026-01-15T10:30:00Z"
}
```

Запрос:

```powershell
curl.exe -k -i -X PUT "https://localhost/info/$md5" `
  -H "Content-Type: application/json" `
  -H "X-API-Key: $apiKey" `
  --data-binary "@update.json"
```

При успешном обновлении возвращается `200 OK`.

Если запись не найдена, возвращается `404 Not Found`. PUT не создаёт новую запись.

### Обработка ошибок

| HTTP-статус | Описание |
|---|---|
| `400` | Некорректные входные данные |
| `401` | Отсутствует или неверен API-ключ |
| `404` | Запись не найдена |
| `409` | Запись с таким MD5 уже существует |
| `429` | Превышен лимит запросов |
| `500` | Внутренняя ошибка сервера |

Ошибки приложения возвращаются в формате JSON с полем `message` и при необходимости `details`.

## Защита сервиса

В проекте реализованы следующие механизмы:

- **HTTPS** — Nginx принимает HTTPS-запросы и перенаправляет HTTP на HTTPS.
- **API-ключ** — для POST и PUT требуется заголовок `X-API-Key`.
- **Rate limiting** — ограничение 10 запросов в секунду на IP с `burst = 20`.
- **Валидация** — проверка MD5, названия и допустимых значений полей.
- **Ограничение размера запросов** — JSON ограничен 1 МиБ, неизвестные поля отклоняются.
- **Доверенный прокси** — заголовок `X-Real-IP` учитывается только для настроенного доверенного прокси.
- **Тайм-ауты** — ограничение времени чтения и записи HTTP-запросов.

Конфигурация предназначена для локального запуска и проверки тестового задания.

## Кодогенерация OpenAPI

Для генерации Go-моделей и HTTP-интерфейса используется `oapi-codegen`.

Исходная спецификация находится в `api/openapi.yaml`, настройки генератора — в `api/oapi-codegen.yaml`.

Установите генератор:

```powershell
go install github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@v2.8.2
```

Для повторной генерации выполните:

```powershell
powershell -ExecutionPolicy Bypass -File .\generate.ps1
```

Скрипт обновляет `internal/api/generated/api.gen.go`, выполняет `go mod tidy` и проверяет сборку проекта.

Сгенерированный код используется для регистрации маршрутов и реализации интерфейса `ServerInterface`. Адаптер `internal/handler/generated_adapter.go` связывает его с обработчиками приложения.

## Тестирование

Для запуска тестов необходим Go версии, указанной в `go.mod`.

Модульные тесты:

```powershell
go test ./... -count=1
```

Статический анализ:

```powershell
go vet ./...
```

Тестами покрыты основные операции с моделью угрозы, бизнес-логика, HTTP-обработчики и middleware.

### Интеграционные тесты

Интеграционные тесты репозитория проверяют работу с настоящей PostgreSQL. Для них используется отдельная база данных `threats_test`, чтобы не затрагивать данные основного приложения.

Сначала запустите PostgreSQL:

```powershell
docker compose up -d postgres
```

Создайте тестовую базу:

```powershell
docker compose exec -T postgres psql -U threat_user -d postgres -c "CREATE DATABASE threats_test OWNER threat_user;"
```

Если база уже существует, создавать её повторно не нужно.

Примените миграцию:

```powershell
Get-Content -Raw -Encoding UTF8 .\migrations\001_create_threats.sql |
  docker compose exec -T postgres psql -v ON_ERROR_STOP=1 -U threat_user -d threats_test
```

Если таблицы уже созданы, повторять миграцию не требуется.

Для запуска интеграционных тестов используется Go-контейнер, подключённый к Docker-сети PostgreSQL:

```powershell
$goModCache = (go env GOMODCACHE).Trim()

docker run --rm `
  --network threat-information-service_backend `
  -v "${PWD}:/app" `
  -v "${goModCache}:/go/pkg/mod:ro" `
  -w /app `
  -e GOPROXY=off `
  -e DATABASE_URL="postgres://threat_user:ВАШ_ПАРОЛЬ@postgres:5432/threats_test?sslmode=disable" `
  golang:1.26-alpine `
  sh -c "go test ./internal/repository/... -count=1 -v"
```

В строке подключения необходимо указать пароль PostgreSQL из `.env`.

В примере используется сеть `threat-information-service_backend`, созданная Docker Compose для этого проекта. Если имя проекта или каталога отличается, название сети может измениться.

Посмотреть доступные сети можно командой:

```powershell
docker network ls
```

Найдите сеть, к которой подключён PostgreSQL, и укажите её имя в параметре `--network`.

Команда использует локальный кэш Go-модулей (`GOPROXY=off`), поэтому зависимости должны быть предварительно загружены на компьютере.

Если переменная `DATABASE_URL` не задана, интеграционные тесты, требующие подключения к PostgreSQL, пропускаются.

## Структура проекта

```text
api/                     OpenAPI-спецификация и настройки генератора
cmd/server/              Точка входа приложения
internal/api/generated/  Сгенерированный Go-код
internal/domain/         Модель угрозы и валидация
internal/handler/        HTTP-обработчики, адаптер и middleware
internal/service/        Бизнес-логика
internal/repository/     Работа с PostgreSQL
migrations/              SQL-миграции
nginx/                   Конфигурация HTTPS-прокси
compose.yaml             Конфигурация Docker Compose
Dockerfile               Сборка Go-приложения
generate.ps1             Скрипт кодогенерации
.env.example             Шаблон переменных окружения
```

Файл `.env` и локальные TLS-сертификаты создаются при настройке окружения и не включаются в репозиторий.
