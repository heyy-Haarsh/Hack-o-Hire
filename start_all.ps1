# ============================================================
# FraudShield — Start All Services
# Ports: 8005 (Prompt Guard) | 8001 (Email API) | 8000 (Voice API)
# Shared venv: fraudshield-voice\venv
# Run from: Hack-O-Hire root directory
# ============================================================

$ROOT    = Split-Path -Parent $MyInvocation.MyCommand.Definition
$VENV    = Join-Path $ROOT "fraudshield-voice\venv\Scripts\activate.ps1"
$PYTHON  = Join-Path $ROOT "fraudshield-voice\venv\Scripts\python.exe"

Write-Host ""
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  FraudShield — Starting All Services  " -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host "  Shared venv : fraudshield-voice\venv  " -ForegroundColor Gray
Write-Host ""

# ── 1. Prompt Guard (MUST start first — middleware for all others) ──
Write-Host "[1/3] Starting Prompt Guard on port 8005..." -ForegroundColor Yellow
$guardPath = Join-Path $ROOT "fraudshield-prompt-guard"
Start-Process powershell -ArgumentList @(
    "-NoExit",
    "-Command",
    "cd '$guardPath'; Write-Host '[PromptGuard] Activating venv...' -ForegroundColor Green; & '$VENV'; python src\api.py"
) -WindowStyle Normal

Write-Host "   Waiting 12s for Prompt Guard to load transformer model..." -ForegroundColor Gray
Start-Sleep -Seconds 12

# ── 2. Email API ───────────────────────────────────────────────────
Write-Host "[2/3] Starting Email API on port 8001..." -ForegroundColor Yellow
$emailPath = Join-Path $ROOT "fraudshield-email"
Start-Process powershell -ArgumentList @(
    "-NoExit",
    "-Command",
    "cd '$emailPath'; Write-Host '[Email API] Activating venv...' -ForegroundColor Green; & '$VENV'; python src\api.py"
) -WindowStyle Normal

Write-Host "   Waiting 8s for Email API to load RoBERTa model..." -ForegroundColor Gray
Start-Sleep -Seconds 8

# ── 3. Voice API ───────────────────────────────────────────────────
Write-Host "[3/3] Starting Voice API on port 8000..." -ForegroundColor Yellow
$voicePath = Join-Path $ROOT "fraudshield-voice"
Start-Process powershell -ArgumentList @(
    "-NoExit",
    "-Command",
    "cd '$voicePath'; Write-Host '[Voice API] Activating venv...' -ForegroundColor Green; & '$VENV'; python src\api.py"
) -WindowStyle Normal

Start-Sleep -Seconds 3

# ── Summary ────────────────────────────────────────────────────────
Write-Host ""
Write-Host "========================================" -ForegroundColor Green
Write-Host "  All services launched!                " -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host ""
Write-Host "  Prompt Guard : http://localhost:8005/health" -ForegroundColor Cyan
Write-Host "  Email API    : https://localhost:8001/health" -ForegroundColor Cyan
Write-Host "  Voice API    : http://localhost:8000/health" -ForegroundColor Cyan
Write-Host ""
Write-Host "  API Docs:" -ForegroundColor White
Write-Host "  Prompt Guard : http://localhost:8005/docs" -ForegroundColor Gray
Write-Host "  Email API    : https://localhost:8001/docs" -ForegroundColor Gray
Write-Host "  Voice API    : http://localhost:8000/docs" -ForegroundColor Gray
Write-Host ""
Write-Host "  Run tests    : & '$PYTHON' test_prompt_guard.py" -ForegroundColor Yellow
Write-Host ""
Write-Host "========================================" -ForegroundColor Magenta
Write-Host "  n8n Incident Response                 " -ForegroundColor Magenta
Write-Host "========================================" -ForegroundColor Magenta
Write-Host ""
Write-Host "  Step 1 — Start n8n (run ONCE, separate terminal):" -ForegroundColor White
Write-Host "           npx n8n" -ForegroundColor Yellow
Write-Host ""
Write-Host "  Step 2 — Open n8n editor:" -ForegroundColor White
Write-Host "           http://localhost:5678" -ForegroundColor Yellow
Write-Host ""
Write-Host "  Step 3 — Import workflow:" -ForegroundColor White
Write-Host "           n8n\fraudshield_workflow.json" -ForegroundColor Yellow
Write-Host ""
Write-Host "  Step 4 — Activate the workflow (toggle in n8n UI)" -ForegroundColor White
Write-Host ""
Write-Host "  n8n Status  : https://localhost:8001/n8n/status" -ForegroundColor Cyan
Write-Host ""
