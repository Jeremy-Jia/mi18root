@echo off
chcp 65001 >nul
setlocal
set "BASE=%~dp0"
set "RUNTIME=%BASE%runtime\win"
set "PYTHON=%RUNTIME%\python\python.exe"
set "ADB=%RUNTIME%\platform-tools\adb.exe"
set "PWSH=%SystemRoot%\System32\WindowsPowerShell\v1.0\powershell.exe"
if exist "%RUNTIME%\powershell\pwsh.exe" set "PWSH=%RUNTIME%\powershell\pwsh.exe"
if not exist "%PWSH%" (
    echo Windows PowerShell 5.1 was not found. Windows 10/11 is required.
    exit /b 1
)

if not exist "%PYTHON%" goto bootstrap
if not exist "%ADB%" goto bootstrap
goto run

:bootstrap
echo Windows runtime missing; downloading portable Python and Android platform-tools...
"%PWSH%" -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%BASE%bootstrap\bootstrap-windows.ps1"
if errorlevel 1 (
    echo Runtime setup failed.
    exit /b 1
)

:run
if not exist "%PWSH%" (
    echo Windows PowerShell 5.1 was not found. Windows 10/11 is required.
    exit /b 1
)
"%PWSH%" -NoLogo -NoProfile -ExecutionPolicy Bypass -File "%BASE%tool\oneclick-root.ps1" -AdbPath "%ADB%" -PythonPath "%PYTHON%" %*
exit /b %errorlevel%
