@echo off
setlocal

cd /d "%~dp0"

where npm >nul 2>nul
if errorlevel 1 (
  echo [ERROR] npm is not installed or not available in PATH.
  echo Please install Node.js, then run this file again.
  pause
  exit /b 1
)

if not exist "node_modules" (
  echo [SETUP] Installing frontend dependencies...
  call npm.cmd install
  if errorlevel 1 (
    echo [ERROR] npm install failed.
    pause
    exit /b 1
  )
)

if not exist "node_modules\\react-router-dom" (
  echo [SETUP] Missing react-router-dom. Installing dependencies...
  call npm.cmd install
  if errorlevel 1 (
    echo [ERROR] npm install failed while installing react-router-dom.
    pause
    exit /b 1
  )
)

if not exist "node_modules\\recharts" (
  echo [SETUP] Missing recharts. Installing dependencies...
  call npm.cmd install
  if errorlevel 1 (
    echo [ERROR] npm install failed while installing recharts.
    pause
    exit /b 1
  )
)

echo [START] Launching SOC dashboard frontend...
call npm.cmd run dev

if errorlevel 1 (
  echo [ERROR] Failed to start the frontend server.
  pause
  exit /b 1
)

endlocal
