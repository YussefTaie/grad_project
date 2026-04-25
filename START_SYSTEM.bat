@echo off
title IDS/IPS SOC — Diagnostic + Launcher
color 0A
cls

set "PROJECT=d:\CIC\Last semester 2026\Graduation Project\MachineLearning\Cyber-Attack-AI"
set "FRONTEND=%PROJECT%\frontend"

echo.
echo  ============================================================
echo   IDS/IPS SOC System — Diagnostic ^& Launcher
echo  ============================================================
echo.

:: ── Step 1: Python ────────────────────────────────────────────
echo [1/7] Checking Python...
python --version >nul 2>&1
if errorlevel 1 (
    echo  [ERROR] Python not found. Install from https://python.org
    pause & exit /b 1
)
for /f "tokens=*" %%v in ('python --version 2^>^&1') do echo  [OK] %%v

:: ── Step 2: Port 5000 free? ───────────────────────────────────
echo [2/7] Checking if port 5000 is free...
netstat -ano | findstr ":5000 " >nul 2>&1
if not errorlevel 1 (
    echo  [WARN] Port 5000 is already in use.
    echo  [INFO] Killing existing process on port 5000...
    for /f "tokens=5" %%p in ('netstat -ano ^| findstr ":5000 "') do (
        taskkill /PID %%p /F >nul 2>&1
    )
    timeout /t 2 /nobreak >nul
    echo  [OK] Port 5000 cleared.
) else (
    echo  [OK] Port 5000 is free.
)

:: ── Step 3: flask-cors installed? ─────────────────────────────
echo [3/7] Checking flask-cors...
python -c "import flask_cors" >nul 2>&1
if errorlevel 1 (
    echo  [*] Installing flask-cors...
    pip install flask-cors --quiet
    if errorlevel 1 (
        echo  [ERROR] pip install failed. Run: pip install flask-cors
        pause & exit /b 1
    )
)
echo  [OK] flask-cors ready.

:: ── Step 4: asyncpg installed? ────────────────────────────────
echo [4/7] Checking asyncpg...
python -c "import asyncpg" >nul 2>&1
if errorlevel 1 (
    echo  [*] Installing asyncpg...
    pip install asyncpg --quiet
)
echo  [OK] asyncpg ready.

:: ── Step 5: api.py exists? ────────────────────────────────────
echo [5/7] Verifying api.py...
if not exist "%PROJECT%\api.py" (
    echo  [ERROR] api.py not found in %PROJECT%
    pause & exit /b 1
)
echo  [OK] api.py found.

:: ── Step 6: npm install if missing ────────────────────────────
echo [6/7] Checking frontend node_modules...
if not exist "%FRONTEND%\node_modules" (
    echo  [*] Running npm install...
    cd /d "%FRONTEND%"
    npm install --silent
    echo  [OK] npm install done.
) else (
    echo  [OK] node_modules present.
)

:: ── Step 7: PostgreSQL running? ───────────────────────────────
echo [7/7] Checking PostgreSQL service...
sc query postgresql* 2>nul | findstr "RUNNING" >nul 2>&1
if errorlevel 1 (
    echo  [WARN] PostgreSQL service not detected — DB features may show fallback data.
    echo  [INFO] Start PostgreSQL from Services or pgAdmin if needed.
) else (
    echo  [OK] PostgreSQL is running.
)

echo.
echo  ============================================================
echo   All checks passed. Starting system...
echo  ============================================================
echo.

:: ── Start Flask Backend on port 5000 ──────────────────────────
echo  [STARTING] Flask Backend on http://127.0.0.1:5000 ...
start "SOC Backend — Flask :5000" cmd /k ^
    "cd /d "%PROJECT%" && echo. && ^
     echo  Backend: http://127.0.0.1:5000 && ^
     echo  Health:  http://127.0.0.1:5000/health && ^
     echo  Alerts:  http://127.0.0.1:5000/alerts && ^
     echo. && ^
     python api.py"

:: Wait for Flask to boot
timeout /t 4 /nobreak >nul

:: ── Test Backend is responding ────────────────────────────────
echo  [TEST] Verifying backend is reachable...
python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:5000/health', timeout=5); print('  [OK] Backend is UP')" 2>nul
if errorlevel 1 (
    echo  [WARN] Backend might still be loading... continuing anyway.
)

:: ── Start React Frontend ──────────────────────────────────────
echo  [STARTING] React Frontend on http://localhost:5173 ...
start "SOC Frontend — React :5173" cmd /k ^
    "cd /d "%FRONTEND%" && echo. && ^
     echo  Dashboard: http://localhost:5173 && ^
     echo. && ^
     npm run dev"

:: Wait for Vite to boot
timeout /t 5 /nobreak >nul

:: ── Open Browser ──────────────────────────────────────────────
echo  [BROWSER] Opening dashboard...
start "" "http://localhost:5173"

echo.
echo  ============================================================
echo.
echo   SYSTEM IS RUNNING
echo.
echo   Dashboard   :  http://localhost:5173
echo   Backend API :  http://127.0.0.1:5000
echo   Health      :  http://127.0.0.1:5000/health
echo   Alerts      :  http://127.0.0.1:5000/alerts
echo   Detections  :  http://127.0.0.1:5000/detections
echo   Flows       :  http://127.0.0.1:5000/flows
echo.
echo   NOTE: The backend runs on port 5000 (Flask), NOT 8000.
echo         The dashboard auto-connects to port 5000.
echo.
echo   Close the two black terminal windows to stop the system.
echo.
echo  ============================================================
echo.
pause
