@echo off
title File Cleanup Tool
echo ============================================================
echo   File Cleanup Tool - Starting...
echo   Browser will open at http://localhost:8080
echo   Press Ctrl+C to stop the server.
echo ============================================================
echo.
python "%~dp0file_cleanup.py"
pause
