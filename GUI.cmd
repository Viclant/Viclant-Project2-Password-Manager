@echo off
cd /d "%~dp0"
if not exist ".venv\Scripts\pythonw.exe" (
  echo Run Setup.cmd first, then open GUI.cmd again.
  pause
  exit /b 1
)
".venv\Scripts\python.exe" -c "import tkinter; import gui_session" >nul 2>nul
if errorlevel 1 (
  echo The desktop UI needs Python with Tcl/Tk and the project dependencies.
  echo Use the official Python installer with the Tcl/Tk option, then run Setup.cmd.
  pause
  exit /b 1
)
start "" ".venv\Scripts\pythonw.exe" "%~dp0vault_gui.py"
