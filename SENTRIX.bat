@echo off
title SENTRIX v3.0 Launcher
cd /d "%~dp0"

if exist "venv\Scripts\python.exe" (
    start "" "venv\Scripts\pythonw.exe" main.py
) else (
    start "" pythonw.exe main.py
)
exit
