Threat Information Service
Небольшой REST API-сервис для хранения информации о компьютерных угрозах. Записи идентифицируются по MD5-хешу файла. Сервис написан на Go, данные хранятся в PostgreSQL. HTTP-интерфейс реализован по [OpenAPI-спецификации](api/openapi.yaml) из задания.
Что умеет сервис
- Создавать запись об угрозе (POST /info).
- Получать информацию по MD5 (GET /info/{md5}).
- Обновлять существующую запись (PUT /info/{md5}).
- Проверять входные данные и возвращать ошибки в JSON.
- Ограничивать частоту запросов и проверять API-ключ для операций записи.
Для запуска используются Docker Compose и Nginx с HTTPS. Есть модульные и интеграционные тесты.
Стек
- Go — HTTP API, валидация и работа с данными.
- PostgreSQL 17 — база данных.
- Docker Compose — запуск приложения и его зависимостей.
- Nginx — HTTPS и проксирование запросов.
- OpenAPI 3.0 — описание API.
Модель угрозы
К исходным полям md5 и name добавлены поля с описанием, классификацией и датами:
Поле	Назначение
md5	MD5-хеш файла, уникальный ключ записи
name	Название угрозы
description	Описание
threat_type	Тип угрозы
severity	Уровень опасности
first_seen_at	Когда угроза была впервые обнаружена
created_at	Когда запись создана
updated_at	Когда запись обновлялась в последний раз


Для threat_type доступны значения trojan, virus, worm, ransomware, spyware, other. Для severity — low, medium, high, critical.

MD5 должен состоять из 32 шестнадцатеричных символов. Название обязательно, его длина ограничена 255 символами. Даты передаются в формате RFC 3339, например 2026-01-15T10:30:00Z.
Запуск
Нужны Docker и Docker Compose. Примеры команд приведены для Windows PowerShell. Выполнять их нужно из корня проекта.
1. Создать .env
Copy-Item .env.example .env
В .env нужно указать настройки PostgreSQL и значение API_KEY. Пароль базы и API-ключ следует заменить на свои. Файл .env добавлен в .gitignore.
2. Создать сертификат для HTTPS
Nginx использует файлы certs/server.crt и certs/server.key. В репозитории их нет, поэтому перед первым запуском нужно создать самоподписанный сертификат.
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
OpenSSL запускается в контейнере, отдельно устанавливать его не нужно. Сертификат предназначен только для локального запуска. Приватный ключ server.key нельзя выкладывать в репозиторий; каталог certs/ исключён из Git.
3. Запустить сервис
docker compose up --build -d
Проверить контейнеры:
docker compose ps
Если что-то не запустилось, посмотреть логи:
docker compose logs --tail=100
При первом запуске PostgreSQL инициализируется SQL-скриптом из migrations/. Если том базы уже существует, скрипт повторно не выполняется.
4. Проверить API
curl.exe -k https://localhost/healthz
Ожидаемый ответ:
{"status":"ok"}
Сервис доступен по адресу https://localhost. Флаг -k нужен для локальной проверки с самоподписанным сертификатом. В рабочем окружении проверку сертификата отключать нельзя.

Остановить контейнеры можно командой:
docker compose down
Данные PostgreSQL при этом сохраняются в Docker-томе. Команда docker compose down -v удалит и том с данными.
API
Метод	Адрес	Что делает	API-ключ
POST	/info	Создаёт угрозу	Да
GET	/info/{md5}	Возвращает угрозу по MD5	Нет
PUT	/info/{md5}	Обновляет угрозу	Да
GET	/healthz	Проверяет доступность сервера	Нет


Авторизация
Для POST и PUT требуется заголовок X-API-Key. Его значение должно совпадать с API_KEY в .env. Если ключ отсутствует или неверный, сервис возвращает 401 Unauthorized.

Чтобы не вводить ключ в каждой команде PowerShell, можно считать его из .env:
$key = ((Get-Content .env | Where-Object { $_ -match '^API_KEY=' } | Select-Object -First 1) -replace '^API_KEY=', '').Trim()
Команда рассчитана на запись API_KEY=значение без кавычек.
Создание записи
POST /info

Пример JSON:
{
  "md5": "5d41402abc4b2a76b9719d911017c592",
  "name": "Trojan.Win32.Generic",
  "description": "Вредоносная программа",
  "threat_type": "trojan",
  "severity": "high",
  "first_seen_at": "2026-01-15T10:30:00Z"
}
Пример запроса из PowerShell:
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
При успешном создании возвращается 201 Created. Если запись с таким MD5 уже существует — 409 Conflict.
Получение записи
GET /info/{md5}
curl.exe -k -i https://localhost/info/5d41402abc4b2a76b9719d911017c592
Если запись найдена, сервер возвращает 200 OK и JSON с информацией об угрозе. Если нет — 404 Not Found. Неверный формат MD5 приводит к 400 Bad Request.
Обновление записи
PUT /info/{md5}

MD5 указывается в адресе, обновлённые поля — в JSON-теле запроса.
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
При успешном обновлении возвращается 200 OK, если запись не найдена — 404 Not Found.
Ошибки
Ошибки возвращаются в JSON. Например:
{
  "message": "Threat not found"
}
В некоторых ответах также присутствует поле details.

Основные HTTP-статусы:
Статус	Причина
400	Некорректный запрос
401	Неверный или отсутствующий API-ключ
404	Угроза не найдена
409	MD5 уже существует
429	Превышен лимит запросов
500	Внутренняя ошибка сервера


Схемы запросов и ответов подробно описаны в [`api/openapi.yaml`](api/openapi.yaml).
Защита
Для тестового проекта добавлены несколько базовых мер защиты:
- HTTPS. Nginx принимает HTTPS-запросы на порту 443, а HTTP-запросы перенаправляет на HTTPS.
- API-ключ. Создание и обновление угроз доступны только с правильным X-API-Key.
- Rate limiting. Для каждого клиентского IP установлен лимит 10 запросов в секунду с burst = 20. При превышении возвращается 429.
- Проверка IP. Заголовок X-Real-IP используется только если запрос пришёл от доверенного прокси. В Docker Compose это Nginx с адресом 172.30.10.10/32, заданным через TRUSTED_PROXY_CIDR.
- Проверка JSON. Тело запроса ограничено 1 МиБ; неизвестные поля и некорректный JSON отклоняются.
В Docker Compose внешний доступ к Nginx и PostgreSQL привязан к 127.0.0.1. Настройки рассчитаны на локальное тестирование, а не на публикацию сервиса в интернете.
Тесты
Запустить все тесты:
go test -count=1 ./...
В проекте есть тесты модели, HTTP-обработчиков, middleware и репозитория. Интеграционные тесты репозитория используют PostgreSQL. Если DATABASE_URL не задан, они пропускаются.

Для запуска интеграционных тестов можно поднять базу:
docker compose up -d postgres
Затем задать DATABASE_URL с параметрами из своего .env. Например, для стандартных имени пользователя, базы и порта из .env.example:
$env:DATABASE_URL = "postgres://threat_user:ВАШ_ПАРОЛЬ@localhost:15432/threats_db?sslmode=disable"

go test -count=1 -v ./internal/repository/...

Remove-Item Env:DATABASE_URL
Если пароль содержит специальные символы URL, их нужно закодировать в строке подключения.
Структура проекта
.
├── api/
│   └── openapi.yaml
├── cmd/server/
│   └── main.go
├── internal/
│   ├── domain/          # Модель и валидация
│   ├── handler/         # HTTP-обработчики и middleware
│   └── repository/      # Запросы к PostgreSQL
├── migrations/          # SQL для создания таблицы
├── nginx/               # Конфигурация Nginx
├── certs/               # Локальные сертификаты, не в Git
├── .env.example
├── compose.yaml
├── Dockerfile
└── README.md