@echo off
setlocal

cd /d "%~dp0frontend"

where npm >nul 2>nul
if errorlevel 1 (
  echo [ERROR] npm is not installed or not available in PATH.
  echo Please install Node.js, then run this file again.
  pause
  exit /b 1
)

if not exist "node_modules" (
  echo [SETUP] Installing frontend dependencies...
  call npm install
  if errorlevel 1 (
    echo [ERROR] npm install failed.
    pause
    exit /b 1
  )
)

echo [START] Launching SOC dashboard frontend...
call npm run dev

if errorlevel 1 (
  echo [ERROR] Failed to start the frontend server.
  pause
  exit /b 1
)

endlocal
