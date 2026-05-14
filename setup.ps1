#Requires -Version 5.1
<#
.SYNOPSIS
    Reversio - Windows Docker Environment Setup Script

.DESCRIPTION
    Sets up the full Reversio development environment on Windows using Docker:
    - Verifies Docker Desktop is running
    - Creates required local directories
    - Builds and starts all containers (Reversio app, Qdrant, Ollama)
    - Pulls the required Ollama embedding model
    - Verifies all services are healthy

.NOTES
    Prerequisites:
    - Docker Desktop for Windows (with WSL 2 backend)
    - NVIDIA GPU + NVIDIA Container Toolkit (optional, for GPU-accelerated Ollama)
    - At least 8 GB free RAM, 15 GB disk space
#>

param(
    [switch]$NoBuild,
    [switch]$GpuDisable,
    [switch]$Down
)

$ErrorActionPreference = "Stop"
$PROJECT_ROOT = Split-Path -Parent $MyInvocation.MyCommand.Path

Write-Host ""
Write-Host "=== Reversio Docker Setup ===" -ForegroundColor Cyan
Write-Host ""

# --- Teardown mode ---
if ($Down) {
    Write-Host "[*] Stopping and removing containers..." -ForegroundColor Yellow
    docker compose -f "$PROJECT_ROOT\docker-compose.yml" down -v
    Write-Host "[+] Environment torn down." -ForegroundColor Green
    exit 0
}

# --- Check Docker ---
Write-Host "[1/6] Checking Docker..." -ForegroundColor Yellow
try {
    $dockerVersion = docker version --format '{{.Server.Version}}' 2>$null
    if (-not $dockerVersion) { throw "Docker not responding" }
    Write-Host "      Docker Engine $dockerVersion detected." -ForegroundColor Green
} catch {
    Write-Host "      ERROR: Docker is not running or not installed." -ForegroundColor Red
    Write-Host "      Install Docker Desktop: https://docs.docker.com/desktop/install/windows-install/" -ForegroundColor Red
    exit 1
}

# --- Check Docker Compose ---
Write-Host "[2/6] Checking Docker Compose..." -ForegroundColor Yellow
try {
    $composeVersion = docker compose version --short 2>$null
    if (-not $composeVersion) { throw "Compose not found" }
    Write-Host "      Docker Compose $composeVersion detected." -ForegroundColor Green
} catch {
    Write-Host "      ERROR: Docker Compose not available." -ForegroundColor Red
    Write-Host "      It should be included with Docker Desktop." -ForegroundColor Red
    exit 1
}

# --- Create directories ---
Write-Host "[3/6] Creating local directories..." -ForegroundColor Yellow

$directories = @(
    "$PROJECT_ROOT\data",
    "$PROJECT_ROOT\samples"
)

foreach ($dir in $directories) {
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
        Write-Host "      Created: $dir" -ForegroundColor Gray
    } else {
        Write-Host "      Exists:  $dir" -ForegroundColor Gray
    }
}

# --- Handle GPU configuration ---
Write-Host "[4/6] Checking GPU availability..." -ForegroundColor Yellow

$composeFile = "$PROJECT_ROOT\docker-compose.yml"
$useGpu = $false

if (-not $GpuDisable) {
    try {
        $nvidiaCheck = docker run --rm --gpus all nvidia/cuda:12.0.0-base-ubuntu22.04 nvidia-smi 2>$null
        if ($LASTEXITCODE -eq 0) {
            $useGpu = $true
            Write-Host "      NVIDIA GPU detected. Ollama will use GPU acceleration." -ForegroundColor Green
        }
    } catch {
        # GPU not available
    }
}

if (-not $useGpu) {
    Write-Host "      No GPU detected (or -GpuDisable set). Using CPU-only mode." -ForegroundColor Gray
    Write-Host "      Creating CPU-only override..." -ForegroundColor Gray

    $overrideContent = @"
services:
  ollama:
    deploy: {}
"@
    $overrideContent | Out-File -FilePath "$PROJECT_ROOT\docker-compose.override.yml" -Encoding utf8
}

# --- Build and start ---
Write-Host "[5/6] Building and starting services..." -ForegroundColor Yellow

$composeArgs = @("-f", $composeFile)
if (Test-Path "$PROJECT_ROOT\docker-compose.override.yml") {
    $composeArgs += @("-f", "$PROJECT_ROOT\docker-compose.override.yml")
}

if ($NoBuild) {
    Write-Host "      Skipping build (using cached images)..." -ForegroundColor Gray
    docker compose @composeArgs up -d
} else {
    Write-Host "      Building Reversio image (this may take a few minutes on first run)..." -ForegroundColor Gray
    docker compose @composeArgs up -d --build
}

if ($LASTEXITCODE -ne 0) {
    Write-Host "      ERROR: docker compose up failed." -ForegroundColor Red
    exit 1
}

# --- Verify services ---
Write-Host "[6/6] Verifying services..." -ForegroundColor Yellow

$maxRetries = 30
$retryDelay = 3

# Wait for Qdrant
Write-Host "      Waiting for Qdrant..." -ForegroundColor Gray
for ($i = 0; $i -lt $maxRetries; $i++) {
    try {
        $response = Invoke-RestMethod -Uri "http://localhost:6333/readyz" -Method Get -TimeoutSec 2 2>$null
        Write-Host "      Qdrant is ready (port 6333)." -ForegroundColor Green
        break
    } catch {
        if ($i -eq ($maxRetries - 1)) {
            Write-Host "      WARNING: Qdrant did not become ready in time." -ForegroundColor Red
        }
        Start-Sleep -Seconds $retryDelay
    }
}

# Wait for Ollama
Write-Host "      Waiting for Ollama..." -ForegroundColor Gray
for ($i = 0; $i -lt $maxRetries; $i++) {
    try {
        $response = Invoke-RestMethod -Uri "http://localhost:11434/api/tags" -Method Get -TimeoutSec 2 2>$null
        Write-Host "      Ollama is ready (port 11434)." -ForegroundColor Green
        break
    } catch {
        if ($i -eq ($maxRetries - 1)) {
            Write-Host "      WARNING: Ollama did not become ready in time." -ForegroundColor Red
        }
        Start-Sleep -Seconds $retryDelay
    }
}

# Check if model was pulled
Write-Host "      Verifying embedding model (qwen3-embedding:4b)..." -ForegroundColor Gray
Start-Sleep -Seconds 5
try {
    $tags = Invoke-RestMethod -Uri "http://localhost:11434/api/tags" -Method Get -TimeoutSec 5
    $modelFound = $tags.models | Where-Object { $_.name -like "qwen3-embedding*" }
    if ($modelFound) {
        Write-Host "      Model qwen3-embedding:4b is available." -ForegroundColor Green
    } else {
        Write-Host "      Model still downloading. Check logs: docker logs reversio-ollama-setup" -ForegroundColor Yellow
    }
} catch {
    Write-Host "      Could not verify model status." -ForegroundColor Yellow
}

# --- Done ---
Write-Host ""
Write-Host "=== Setup Complete ===" -ForegroundColor Cyan
Write-Host ""
Write-Host "Services:" -ForegroundColor White
Write-Host "  Reversio App    : docker attach reversio" -ForegroundColor Gray
Write-Host "  Qdrant Dashboard: http://localhost:6333/dashboard" -ForegroundColor Gray
Write-Host "  Ollama API      : http://localhost:11434" -ForegroundColor Gray
Write-Host ""
Write-Host "Usage:" -ForegroundColor White
Write-Host "  Start interactive session:  docker attach reversio" -ForegroundColor Gray
Write-Host "  View logs:                  docker compose logs -f" -ForegroundColor Gray
Write-Host "  Stop everything:            .\setup.ps1 -Down" -ForegroundColor Gray
Write-Host "  Rebuild after code changes: .\setup.ps1" -ForegroundColor Gray
Write-Host ""
