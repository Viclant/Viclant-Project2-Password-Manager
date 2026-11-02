@echo off
if not exist "%~dp0.venv\Scripts\python.exe" (
  echo Run Setup.cmd first to install the local Python environment.
  exit /b 1
)
if "%~1"=="" (
  "%~dp0.venv\Scripts\python.exe" "%~dp0vault.py" --help
  pause
  exit /b 0
)
"%~dp0.venv\Scripts\python.exe" "%~dp0vault.py" %*
