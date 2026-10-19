@echo off
REM ===========================================================================
REM  AutoPortalAuth - Windows launcher
REM ---------------------------------------------------------------------------
REM  IMPORTANT: This file must stay ASCII-only with CRLF line endings.
REM  Do NOT add Chinese characters and do NOT call "chcp" here:
REM  cmd.exe mis-parses LF-only batch files, and after a code page switch it
REM  loses the first character of the next line (so "python" becomes "ython").
REM  All messages and logic live in install.py, which handles UTF-8 safely.
REM ===========================================================================
setlocal
cd /d "%~dp0"

REM Pick the first interpreter that actually runs (skips broken Store aliases).
set "PY="
for %%C in ("python" "py -3" "python3") do (
    if not defined PY (
        %%~C -c "import sys" >nul 2>nul
        if not errorlevel 1 set "PY=%%~C"
    )
)

if not defined PY (
    echo.
    echo [ERROR] No working Python 3 was found.
    echo         Please install Python 3.8+ and tick "Add Python to PATH".
    echo         Download: https://www.python.org/downloads/
    echo.
    pause
    exit /b 1
)

echo Using interpreter: %PY%
%PY% -X utf8 "install.py" %*
set "RC=%ERRORLEVEL%"

endlocal & exit /b %RC%
