@echo off
chcp 65001 > nul
cd /d "%~dp0"
title 한길 인사·근태 서버
where py >nul 2>nul && (py -3 server.py %*) || (python server.py %*)
pause
