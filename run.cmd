@echo off
setlocal
if exist "%~dp0dist\slate\CipherDesk\CipherDesk.exe" (
    start "" "%~dp0dist\slate\CipherDesk\CipherDesk.exe" %*
    exit /b 0
)
if exist "%~dp0dist\CipherDesk\CipherDesk.exe" (
    start "" "%~dp0dist\CipherDesk\CipherDesk.exe" %*
    exit /b 0
)
powershell.exe -NoProfile -ExecutionPolicy Bypass -File "%~dp0run.ps1" %*
if errorlevel 1 (
    echo.
    echo CipherDesk did not start. See the error above.
    pause
    exit /b 1
)
