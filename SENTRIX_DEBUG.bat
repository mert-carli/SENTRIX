@echo off
title SENTRIX v3.0 (Console Mode)
cd /d "%~dp0"

echo [*] SENTRIX v3.0 Cyber Operations Platform baslatiliyor...
if exist "venv\Scripts\python.exe" (
    ".\venv\Scripts\python.exe" main.py
) else (
    python.exe main.py
)

if %ERRORLEVEL% NEQ 0 (
    echo.
    echo [!] Hata olustu. Cikmak icin bir tusa basin...
    pause >nul
)
