@echo off
setlocal
cd /d %~dp0
set GOCACHE=%~dp0..\.gocache
set GOPROXY=off
set GOSUMDB=off
echo === REALITY amortize local E2E ===
go test -tags l2 -count=1 -timeout 180s -v -run "TestE2E_|TestL2_Authorized" .
exit /b %ERRORLEVEL%
