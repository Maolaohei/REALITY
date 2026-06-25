@echo off
REM ============================================================================
REM REALITY Test Runner — 测试控制系统
REM
REM 用法:
REM   test.bat                    标准测试 (L1+L2+L3+L4)
REM   test.bat quick              快速测试 (<30s)
REM   test.bat full               完整测试 (>5min)
REM   test.bat gate               Release Gate (发版前)
REM   test.bat l1                 仅 L1 单元测试
REM   test.bat l2                 仅 L2 握手测试
REM   test.bat l3                 仅 L3 协议测试
REM   test.bat l6                 仅 L6 回归门禁
REM ============================================================================

setlocal enabledelayedexpansion

set START_TIME=%TIME%
set TOTAL_PASS=0
set TOTAL_FAIL=0

echo ========================================
echo   REALITY Test Runner
echo ========================================
echo.

if "%1"=="" goto standard
if "%1"=="quick" goto quick
if "%1"=="full" goto full
if "%1"=="gate" goto gate
if "%1"=="l1" goto l1
if "%1"=="l2" goto l2
if "%1"=="l3" goto l3
if "%1"=="l3e2e" goto l3e2e
if "%1"=="l3prod" goto l3prod
if "%1"=="l4" goto l4
if "%1"=="l5" goto l5
if "%1"=="l6" goto l6
echo Unknown mode: %1
exit /b 1

:quick
echo Mode: QUICK (L1 + L2)
echo.
call :run_level l1 "Unit Tests"
call :run_level l2 "Handshake Tests"
goto summary

:standard
echo Mode: STANDARD (L1 + L2 + L3 + L4)
echo.
call :run_level l1 "Unit Tests"
call :run_level l2 "Handshake Tests"
call :run_level l3 "Protocol Tests"
call :run_level l4 "TLS Compat Tests"
goto summary

:full
echo Mode: FULL (L1 + L2 + L3 + L4 + L5 + L6)
echo.
call :run_level l1 "Unit Tests"
call :run_level l2 "Handshake Tests"
call :run_level l3 "Protocol Tests"
call :run_level l4 "TLS Compat Tests"
call :run_level l5 "Soak Tests"
call :run_level l6 "Regression Gate"
goto summary

:gate
echo Mode: RELEASE GATE (L1 + L2 + L3 + L4 + L6)
echo.
call :run_level l1 "Unit Tests"
call :run_level l2 "Handshake Tests"
call :run_level l3 "Protocol Tests"
call :run_level l4 "TLS Compat Tests"
call :run_level l6 "Regression Gate"
goto summary

:l1
call :run_level l1 "Unit Tests"
goto summary

:l2
call :run_level l2 "Handshake Tests"
goto summary

:l3
call :run_level l3 "Protocol Tests"
goto summary

:l3e2e
call :run_level l3e2e "E2E Tests"
goto summary

:l3prod
call :run_level l3prod "Production Tests"
goto summary

:l4
call :run_level l4 "TLS Compat Tests"
goto summary

:l5
call :run_level l5 "Soak Tests"
goto summary

:l6
call :run_level l6 "Regression Gate"
goto summary

:run_level
echo [%~2]
go test -v -tags %~1 -count=1 -timeout=300s . 2>&1
if %ERRORLEVEL% EQU 0 (
    echo   PASS: %~2
    set /a TOTAL_PASS+=1
) else (
    echo   FAIL: %~2
    set /a TOTAL_FAIL+=1
)
echo.
goto :eof

:summary
echo ========================================
echo   Results
echo ========================================
echo   Passed: %TOTAL_PASS%
echo   Failed: %TOTAL_FAIL%
echo   Time:   %START_TIME% ^> %TIME%
echo.
if %TOTAL_FAIL% EQU 0 (
    echo   Result: PASS
    echo   Ready for: git tag reality-vNext
) else (
    echo   Result: FAIL
)
echo ========================================

if %TOTAL_FAIL% GTR 0 exit /b 1
exit /b 0
