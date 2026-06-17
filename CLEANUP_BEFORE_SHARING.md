# Cleanup Checklist Before Sharing Code

## 🔴 CRITICAL - Must Remove (Contains Sensitive Data)

### 1. **Delete User Data Folders**
```bash
# Remove all generated data directories
rm -rf data/
rm -rf logs/
```

These folders contain:
- ✗ **Private RSA keys** (`data/keys/*_private.pem`)
- ✗ **User accounts and passwords** (`data/users/users.json`)
- ✗ **Encrypted messages** (`data/messages/*.json`)
- ✗ **Active sessions** (`data/sessions.json`)
- ✗ **Security logs** (`logs/*.log`)

### 2. **Delete Python Cache**
```bash
rm -rf __pycache__/
find . -type d -name "__pycache__" -exec rm -rf {} +
find . -type f -name "*.pyc" -delete
find . -type f -name "*.pyo" -delete
```

### 3. **Delete Virtual Environment**
```bash
rm -rf .venv/
```

### 4. **Delete Temporary Files**
```bash
rm -f *.zip
rm -f *.tmp
rm -f *.bak
```

---

## 🟡 RECOMMENDED - Update Before Sharing

### 5. **Update config.py - Change Secret Key**
Edit `config.py` and update:
```python
SECRET_KEY = os.environ.get('FLASK_SECRET_KEY', 'dev-secret-key-change-in-production')
# Change to:
SECRET_KEY = os.environ.get('FLASK_SECRET_KEY', 'CHANGE-THIS-IN-PRODUCTION')
```

### 6. **Set DEBUG to False**
Edit `config.py`:
```python
DEBUG = True  # Set to False in production
# Change to:
DEBUG = False  # Always use False in production
```

### 7. **Review Attack Simulation Usernames**
Check `attack_simulations.py` and templates for any hardcoded test usernames:
- alice
- bob
- Ved
- Zeel

These are fine for demo purposes, but consider removing or documenting them.

---

## ✅ Files to KEEP and Share

### Core Application Files
- ✓ `app.py` - Main Flask application
- ✓ `authentication.py` - Auth system
- ✓ `messaging_system.py` - Messaging logic
- ✓ `crypto_core.py` - Cryptographic functions
- ✓ `attack_simulations.py` - Attack simulation module
- ✓ `logging_system.py` - Logging system
- ✓ `config.py` - Configuration (after updates)
- ✓ `main.py` - Entry point

### Frontend Files
- ✓ `templates/` - All HTML templates
- ✓ `static/` - CSS, JavaScript, images

### Documentation
- ✓ `README.md` - Project documentation
- ✓ `USER_GUIDE.md` - User guide
- ✓ `requirements.txt` - Python dependencies
- ✓ `.gitignore` - Git ignore file

---

## 🚀 Quick Cleanup Script (Windows PowerShell)

Save this as `cleanup.ps1` and run it:

```powershell
# Secure Messaging System - Cleanup Script
Write-Host "Starting cleanup..." -ForegroundColor Cyan

# Remove user data
if (Test-Path "data") {
    Remove-Item -Recurse -Force "data"
    Write-Host "✓ Removed data/ folder" -ForegroundColor Green
}

# Remove logs
if (Test-Path "logs") {
    Remove-Item -Recurse -Force "logs"
    Write-Host "✓ Removed logs/ folder" -ForegroundColor Green
}

# Remove Python cache
Get-ChildItem -Path . -Filter "__pycache__" -Recurse -Directory | Remove-Item -Recurse -Force
Write-Host "✓ Removed __pycache__ folders" -ForegroundColor Green

# Remove virtual environment
if (Test-Path ".venv") {
    Remove-Item -Recurse -Force ".venv"
    Write-Host "✓ Removed .venv/ folder" -ForegroundColor Green
}

# Remove temp files
Remove-Item -Force "*.zip", "*.tmp", "*.bak" -ErrorAction SilentlyContinue
Write-Host "✓ Removed temporary files" -ForegroundColor Green

Write-Host "`nCleanup complete! Ready to share." -ForegroundColor Green
Write-Host "Remember to update SECRET_KEY in config.py" -ForegroundColor Yellow
```

Run with:
```powershell
.\cleanup.ps1
```

---

## 🚀 Quick Cleanup Script (Linux/Mac)

Save this as `cleanup.sh` and run it:

```bash
#!/bin/bash
# Secure Messaging System - Cleanup Script

echo "Starting cleanup..."

# Remove user data
rm -rf data/ && echo "✓ Removed data/ folder"
rm -rf logs/ && echo "✓ Removed logs/ folder"

# Remove Python cache
find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null
find . -type f -name "*.pyc" -delete
echo "✓ Removed Python cache"

# Remove virtual environment
rm -rf .venv/ && echo "✓ Removed .venv/ folder"

# Remove temp files
rm -f *.zip *.tmp *.bak 2>/dev/null
echo "✓ Removed temporary files"

echo ""
echo "Cleanup complete! Ready to share."
echo "Remember to update SECRET_KEY in config.py"
```

Make it executable and run:
```bash
chmod +x cleanup.sh
./cleanup.sh
```

---

## 📦 Creating a Clean Distribution

After cleanup, create a zip file:

### Windows:
```powershell
Compress-Archive -Path * -DestinationPath secure_messaging_clean.zip
```

### Linux/Mac:
```bash
zip -r secure_messaging_clean.zip . -x "*.git*" "*.venv*" "*__pycache__*" "*data/*" "*logs/*"
```

---

## 🔒 Security Reminder

Before sharing:
1. ✅ All user data removed
2. ✅ All private keys deleted
3. ✅ All log files removed
4. ✅ SECRET_KEY changed to placeholder
5. ✅ DEBUG mode set to False
6. ✅ Virtual environment excluded

The recipient will need to:
1. Create their own virtual environment
2. Install dependencies: `pip install -r requirements.txt`
3. Set their own SECRET_KEY (environment variable or config.py)
4. Run the app - data folders will be auto-created
