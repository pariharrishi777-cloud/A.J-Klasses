@echo off
title AJ Klasses Server
cd /d "%~dp0"
:START
node server.js
echo Server stopped. Restarting in 3 seconds...
timeout /t 3 /nobreak >nul
goto START
