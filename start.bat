@echo off
setlocal

set "SCRIPT_DIR=%~dp0"
cd /d "%SCRIPT_DIR%"

set "PYTHON_CMD="
for %%P in (python py) do (
    where %%P >nul 2>&1
    if not errorlevel 1 (
        set "PYTHON_CMD=%%P"
        goto run_app
    )
)

echo [ERROR] Python interpreter not found in PATH. Install Python or add it to PATH.
goto end

:run_app
"%PYTHON_CMD%" wifi_scanner.py

:end
endlocal
