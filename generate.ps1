
$ErrorActionPreference = "Stop"

$generator = Join-Path (go env GOPATH) "bin/oapi-codegen.exe"

if (-not (Test-Path $generator)) {
    throw "oapi-codegen not found. Install it first."
}

New-Item -ItemType Directory -Force "internal/api/generated" | Out-Null

& $generator `
    --config api/oapi-codegen.yaml `
    -o internal/api/generated/api.gen.go `
    api/openapi.yaml

if ($LASTEXITCODE -ne 0) {
    throw "OpenAPI generation failed"
}

go mod tidy
if ($LASTEXITCODE -ne 0) {
    throw "go mod tidy failed"
}

go build ./...
if ($LASTEXITCODE -ne 0) {
    throw "Build failed"
}

Write-Host "OpenAPI generation completed successfully"
