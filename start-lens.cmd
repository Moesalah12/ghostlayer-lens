@echo off
setlocal
cd /d "%~dp0"
where py >nul 2>nul
if %errorlevel% equ 0 (
  py -3 -m lens serve
) else (
  python -m lens serve
)
if errorlevel 1 (
  echo.
  echo Lens could not start. Install Python 3.11 or newer from python.org, then try again.
  pause
)
