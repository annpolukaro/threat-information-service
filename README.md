# Threat Information Service

Небольшой REST API-сервис для хранения информации о компьютерных угрозах. Записи идентифицируются по MD5-хешу файла.

Сервис написан на Go, данные хранятся в PostgreSQL. HTTP-интерфейс реализован на основе [OpenAPI-спецификации](api/openapi.yaml) из задания.

## Возможности

- Создание записи об угрозе (`POST /info`).
- Получение информации по MD5 (`GET /info/{md5}`).
- Обновление существующей записи (`PUT /info/{md5}`).
- Валидация входных данных и обработка ошибок.
- Авторизация по API-ключу для операций записи.
- Ограничение частоты запросов (rate limiting).
- HTTPS через Nginx.
- Модульные и интеграционные тесты.

## Технологии

- **Go** — HTTP API, бизнес-логика и валидация данных.
- **PostgreSQL 17** — хранение информации об угрозах.
- **Docker и Docker Compose** — сборка и запуск сервиса.
- **Nginx** — HTTPS и обратное проксирование.
- **OpenAPI 3.0** — описание HTTP-интерфейса.

## Модель угрозы

Исходная модель из задания содержала только `md5` и `name`. Для более подробного описания угроз добавлены следующие поля:

| Поле | Назначение |
|---|---|
| `md5` | MD5-хеш файла, уникальный идентификатор |
| `name` | Название угрозы |
| `description` | Описание угрозы |
| `threat_type` | Тип угрозы |
| `severity` | Уровень опасности |
| `first_seen_at` | Дата первого обнаружения |
| `created_at` | Дата создания записи |
| `updated_at` | Дата последнего обновления |

Для `threat_type` предусмотрены значения: `trojan`, `virus`, `worm`, `ransomware`, `spyware`, `other`.

Для `severity`: `low`, `medium`, `high`, `critical`.

Основные ограничения:

- MD5 должен содержать ровно 32 шестнадцатеричных символа.
- Название угрозы обязательно и не может превышать 255 символов.
- Даты передаются в формате RFC 3339, например `2026-01-15T10:30:00Z`.

## Запуск проекта

Для запуска нужны Docker и Docker Compose. Примеры команд приведены для Windows PowerShell. Все команды выполняются из корня проекта.

### 1. Настройка окружения

Создать `.env` на основе шаблона:

```powershell
Copy-Item .env.example .env
```

В файле `.env` необходимо указать настройки подключения к PostgreSQL и значение `API_KEY`. Пароль базы данных и API-ключ следует заменить на собственные.

Файл `.env` добавлен в `.gitignore` и не должен попадать в репозиторий.

### 2. Создание сертификата HTTPS

Nginx использует файлы `certs/server.crt` и `certs/server.key`. Они не включены в репозиторий, поэтому перед первым запуском нужно создать самоподписанный сертификат.

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

OpenSSL запускается внутри контейнера, отдельно устанавливать его не нужно.

Сертификат предназначен только для локального тестирования. Приватный ключ `server.key` нельзя публиковать; каталог `certs/` исключён из Git.

### 3. Запуск контейнеров

Собрать и запустить сервис:

```powershell
docker compose up --build -d
```

Проверить состояние контейнеров:

```powershell
docker compose ps
```

Если возникли ошибки, посмотреть логи:

```powershell
docker compose logs --tail=100
```

При первом запуске PostgreSQL создаёт таблицу с помощью SQL-скрипта из каталога `migrations/`. Если Docker-том базы уже существует, скрипт повторно не выполняется.

### 4. Проверка доступности

```powershell
curl.exe -k https://localhost/healthz
```

Ожидаемый ответ:

```json
{
  "status": "ok"
}
```

После запуска API доступен по адресу `https://localhost`.

Флаг `-k` используется только для локальной проверки с самоподписанным сертификатом. В рабочем окружении отключать проверку сертификата нельзя.

### 5. Остановка

Остановить контейнеры:

```powershell
docker compose down
```

Данные PostgreSQL при этом сохраняются в Docker-томе.

Чтобы остановить контейнеры и удалить том с данными:

```powershell
docker compose down -v
```

## API

Сервис предоставляет три основных метода для работы с угрозами и один служебный endpoint.

| Метод | Endpoint | Описание | API-ключ |
|---|---|---|---|
| POST | `/info` | Создание записи | Да |
| GET | `/info/{md5}` | Получение записи | Нет |
| PUT | `/info/{md5}` | Обновление записи | Да |
| GET | `/healthz` | Проверка доступности | Нет |

### Авторизация

Для POST и PUT необходимо передавать заголовок `X-API-Key`. Значение должно совпадать с `API_KEY` из `.env`.

Если ключ отсутствует или указан неправильно, сервер возвращает `401 Unauthorized`.

Для удобства можно считать API-ключ из `.env` в переменную PowerShell:

```powershell
$key = ((Get-Content .env |
  Where-Object { $_ -match '^API_KEY=' } |
  Select-Object -First 1) -replace '^API_KEY=', '').Trim()
```

Команда рассчитана на формат `API_KEY=значение` без кавычек.

### POST /info — создание угрозы

Создаёт новую запись. MD5 должен быть уникальным.

Пример тела запроса:

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

Пример запроса из PowerShell:

```powershell
$body = @{
  md5 = "5d41402abc4b2a76b9719d911017c592"
  name = "Trojan.Win32.Generic"
  description = "Вредоносная программа"
  threat_type = "trojan"
  severity = "high"
  first_seen_at = "2026-01-15T10:30:00Z"
} | ConvertTo-Json -Compress

$body | Set-Content threat-request.json -Encoding utf8

curl.exe -k -i -X POST https://localhost/info `
  -H "Content-Type: application/json" `
  -H "X-API-Key: $key" `
  --data-binary "@threat-request.json"
```

Возможные ответы:

- `201 Created` — запись создана.
- `400 Bad Request` — некорректные данные.
- `401 Unauthorized` — неверный API-ключ.
- `409 Conflict` — запись с таким MD5 уже существует.

### GET /info/{md5} — получение угрозы

Возвращает информацию об угрозе по MD5-хешу.

```powershell
curl.exe -k -i https://localhost/info/5d41402abc4b2a76b9719d911017c592
```

Возможные ответы:

- `200 OK` — запись найдена.
- `400 Bad Request` — некорректный MD5.
- `404 Not Found` — запись не найдена.

### PUT /info/{md5} — обновление угрозы

Обновляет существующую запись. MD5 передаётся в URL, новые значения полей — в теле запроса.

```powershell
$body = @{
  name = "Trojan.Win32.Updated"
  description = "Обновлённое описание"
  threat_type = "trojan"
  severity = "critical"
  first_seen_at = "2026-01-15T10:30:00Z"
} | ConvertTo-Json -Compress

$body | Set-Content threat-update.json -Encoding utf8

curl.exe -k -i -X PUT https://localhost/info/5d41402abc4b2a76b9719d911017c592 `
  -H "Content-Type: application/json" `
  -H "X-API-Key: $key" `
  --data-binary "@threat-update.json"
```

Возможные ответы:

- `200 OK` — запись обновлена.
- `400 Bad Request` — некорректные данные.
- `401 Unauthorized` — неверный API-ключ.
- `404 Not Found` — запись не найдена.

## Обработка ошибок

Ошибки возвращаются в JSON с человекочитаемым описанием.

Пример:

```json
{
  "message": "Threat not found"
}
```

В некоторых ответах дополнительно присутствует поле `details`.

Основные HTTP-статусы:

| Статус | Причина |
|---|---|
| `400` | Некорректный запрос |
| `401` | Отсутствует или неверный API-ключ |
| `404` | Угроза не найдена |
| `409` | Запись с таким MD5 уже существует |
| `429` | Превышен лимит запросов |
| `500` | Внутренняя ошибка сервера |

Полные схемы запросов и ответов описаны в [`api/openapi.yaml`](api/openapi.yaml).

## Безопасность

Для тестового проекта реализованы базовые меры защиты.

**HTTPS**

Nginx принимает HTTPS-запросы на порту 443 и перенаправляет HTTP-запросы на HTTPS.

**API-ключ**

Создание и обновление записей требуют корректного заголовка `X-API-Key`.

**Rate limiting**

Для каждого клиентского IP действует ограничение 10 запросов в секунду с `burst = 20`. При превышении лимита сервер возвращает `429 Too Many Requests`.

**Проверка клиентского IP**

Заголовок `X-Real-IP` используется только для запросов от доверенного прокси.

В Docker Compose таким прокси является Nginx с адресом `172.30.10.10/32`, указанным через `TRUSTED_PROXY_CIDR`.

**Проверка JSON**

Размер тела запроса ограничен 1 МиБ. Некорректный JSON и неизвестные поля отклоняются.

В Docker Compose внешний доступ к Nginx и PostgreSQL привязан к `127.0.0.1`. Настройки рассчитаны на локальное тестирование, а не на публичное размещение сервиса.

## Тестирование

В проекте есть модульные тесты модели, HTTP-обработчиков и middleware, а также интеграционные тесты репозитория с PostgreSQL.

### Модульные тесты

Запуск всех тестов:

```powershell
go test -count=1 ./...
```

Интеграционные тесты репозитория пропускаются, если переменная `DATABASE_URL` не задана.

### Интеграционные тесты

Для запуска интеграционных тестов необходимо поднять PostgreSQL:

```powershell
docker compose up -d postgres
```

Затем задать `DATABASE_URL` с параметрами подключения из `.env`.

Например, для стандартных имени пользователя, базы и порта из `.env.example`:

```powershell
$env:DATABASE_URL = "postgres://threat_user:ВАШ_ПАРОЛЬ@localhost:15432/threats_db?sslmode=disable"
```

Запустить тесты репозитория:

```powershell
go test -count=1 -v ./internal/repository/...
```

После выполнения удалить переменную окружения:

```powershell
Remove-Item Env:DATABASE_URL
```

Если пароль содержит специальные символы URL, их необходимо закодировать в строке подключения.

Интеграционные тесты следует запускать на отдельной тестовой базе, поскольку они создают и удаляют тестовые записи.

## Структура проекта

```text
.
├── api/
│   └── openapi.yaml
├── cmd/
│   └── server/
│       └── main.go
├── internal/
│   ├── domain/          # Модель угрозы и валидация
│   ├── handler/         # HTTP-обработчики и middleware
│   └── repository/      # Работа с PostgreSQL
├── migrations/          # SQL-скрипт создания таблицы
├── nginx/               # Конфигурация Nginx
├── certs/               # Локальные сертификаты (не в Git)
├── .env.example
├── compose.yaml
├── Dockerfile
└── README.md
```
