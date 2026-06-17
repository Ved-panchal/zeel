# Secure Messaging System - Cleanup Script
# Run this before sharing your code to remove sensitive data

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  Secure Messaging System - Cleanup" -ForegroundColor Cyan
Write-Host "========================================`n" -ForegroundColor Cyan

$itemsToRemove = @()

# Check what will be removed
if (Test-Path "data") {
    $itemsToRemove += "data/ folder (user accounts, keys, messages)"
}
if (Test-Path "logs") {
    $itemsToRemove += "logs/ folder (security logs)"
}
if (Test-Path ".venv") {
    $itemsToRemove += ".venv/ folder (virtual environment)"
}
if (Test-Path "__pycache__") {
    $itemsToRemove += "__pycache__/ folders (Python cache)"
}

if ($itemsToRemove.Count -eq 0) {
    Write-Host "✓ Already clean! No sensitive data found." -ForegroundColor Green
    exit
}

Write-Host "The following will be removed:" -ForegroundColor Yellow
foreach ($item in $itemsToRemove) {
    Write-Host "  - $item" -ForegroundColor Yellow
}

Write-Host "`nPress Enter to continue or Ctrl+C to cancel..." -ForegroundColor White
Read-Host

Write-Host "`nRemoving sensitive data..." -ForegroundColor Cyan

# Remove user data
if (Test-Path "data") {
    try {
        Remove-Item -Recurse -Force "data"
        Write-Host "✓ Removed data/ folder" -ForegroundColor Green
    } catch {
        Write-Host "✗ Error removing data/ folder: $_" -ForegroundColor Red
    }
}

# Remove logs
if (Test-Path "logs") {
    try {
        Remove-Item -Recurse -Force "logs"
        Write-Host "✓ Removed logs/ folder" -ForegroundColor Green
    } catch {
        Write-Host "✗ Error removing logs/ folder: $_" -ForegroundColor Red
    }
}

# Remove Python cache
try {
    Get-ChildItem -Path . -Filter "__pycache__" -Recurse -Directory -ErrorAction SilentlyContinue | 
        Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
    Get-ChildItem -Path . -Filter "*.pyc" -Recurse -File -ErrorAction SilentlyContinue | 
        Remove-Item -Force -ErrorAction SilentlyContinue
    Write-Host "✓ Removed __pycache__ folders and .pyc files" -ForegroundColor Green
} catch {
    Write-Host "✗ Error removing Python cache: $_" -ForegroundColor Red
}

# Remove virtual environment
if (Test-Path ".venv") {
    try {
        Remove-Item -Recurse -Force ".venv"
        Write-Host "✓ Removed .venv/ folder" -ForegroundColor Green
    } catch {
        Write-Host "✗ Error removing .venv/ folder: $_" -ForegroundColor Red
    }
}

# Remove temp files
try {
    Remove-Item -Force "*.zip", "*.tmp", "*.bak" -ErrorAction SilentlyContinue
    Write-Host "✓ Removed temporary files (.zip, .tmp, .bak)" -ForegroundColor Green
} catch {
    # Silently ignore if no temp files exist
}

Write-Host "`n========================================" -ForegroundColor Cyan
Write-Host "  Cleanup Complete!" -ForegroundColor Green
Write-Host "========================================`n" -ForegroundColor Cyan

Write-Host "Next steps before sharing:" -ForegroundColor Yellow
Write-Host "  1. Update SECRET_KEY in config.py" -ForegroundColor White
Write-Host "  2. Set DEBUG = False in config.py" -ForegroundColor White
Write-Host "  3. Review CLEANUP_BEFORE_SHARING.md for details" -ForegroundColor White
Write-Host ""
