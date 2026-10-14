:: ============================================================================== 
:: Project Name: USB-STk (USB Security Toolkit)
:: Script Name:  3A1shOnWin.bat
:: Description:  Master launcher for USB-based host reconnaissance and SSH setup.
::               Verifies admin rights, creates the project data structure, and
::               runs the PowerShell modules in a safe sequence while keeping all
::               generated data on the removable USB project root.
:: ============================================================================== 

@echo off
setlocal EnableExtensions EnableDelayedExpansion
title USB-STk - USB Security Toolkit

set "PROJECT_ROOT=%~dp0"
if "%PROJECT_ROOT:~-1%"=="\" set "PROJECT_ROOT=%PROJECT_ROOT:~0,-1%"

set "DATA_DIR=%PROJECT_ROOT%\data"
set "KEYS_DIR=%PROJECT_ROOT%\keys"
set "LOG_DIR=%DATA_DIR%\log\logs"
set "AUDIT_DIR=%DATA_DIR%\log\audit"
set "REPORTS_DIR=%DATA_DIR%\reports"
set "VULN_DIR=%DATA_DIR%\vuln"
set "INFO_DIR=%VULN_DIR%\info"
set "SSH_KEY_DIR=%VULN_DIR%\ssh-key"
set "LOCK_FILE=%DATA_DIR%\.lock"
set "INFO_SCRIPT=%PROJECT_ROOT%\info-3A1shOnWin.ps1"
set "SSH_SCRIPT=%PROJECT_ROOT%\ssh-3A1shOnWin.ps1"
set "LOG_FILE=%LOG_DIR%\logs"
set "AUDIT_FILE=%AUDIT_DIR%\audit"
set "FINAL_RC=0"

rem ------------------------------------------------------------------------------
rem Phase 1: Administrative privilege verification and UAC elevation
rem ------------------------------------------------------------------------------
>nul 2>&1 net session
if errorlevel 1 (
    echo [INFO] [Launcher] Requesting UAC elevation...
    powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -Verb RunAs -Wait -WindowStyle Hidden" >nul 2>&1
    set "UAC_RC=%ERRORLEVEL%"
    if "%UAC_RC%"=="0" exit /b 0
    if "%UAC_RC%"=="1223" (
        echo [ERROR] [Launcher] UAC elevation was cancelled by the user. >&2
        exit /b 1223
    )
    echo [ERROR] [Launcher] Administrator elevation was denied or failed. >&2
    exit /b %UAC_RC%
)

rem ------------------------------------------------------------------------------
rem Phase 2: Validate the project root and USB-only storage requirement
rem ------------------------------------------------------------------------------
if not exist "%PROJECT_ROOT%" (
    echo [ERROR] [Launcher] Project root does not exist: "%PROJECT_ROOT%" >&2
    exit /b 1
)

powershell -NoProfile -ExecutionPolicy Bypass -Command "$p = '%PROJECT_ROOT%'; $driveName = $p.TrimEnd('\\').Substring(0, 2); $drive = [System.IO.DriveInfo]::GetDrives() | Where-Object { $_.Name -eq $driveName }; if (-not $drive) { exit 1 }; if ($drive.DriveType -ne [System.IO.DriveType]::Removable) { exit 2 }"
set "DRIVE_RC=%ERRORLEVEL%"
if not "%DRIVE_RC%"=="0" (
    echo [ERROR] [Launcher] The project must run from a removable USB drive. >&2
    exit /b %DRIVE_RC%
)

rem ------------------------------------------------------------------------------
rem Phase 3: Initialize the full project directory tree on the USB root
rem ------------------------------------------------------------------------------
for %%D in ("%DATA_DIR%" "%KEYS_DIR%" "%LOG_DIR%" "%AUDIT_DIR%" "%REPORTS_DIR%" "%VULN_DIR%" "%INFO_DIR%" "%SSH_KEY_DIR%") do (
    if not exist "%%~D" mkdir "%%~D" 2>nul
    if not exist "%%~D" (
        echo [ERROR] [Launcher] Unable to create required directory: %%~D >&2
        exit /b 1
    )
)

if exist "%DATA_DIR%" attrib +h "%DATA_DIR%" >nul 2>&1
attrib "%DATA_DIR%" | findstr /I /C:"H" >nul
if errorlevel 1 (
    echo [ERROR] [Launcher] Failed to hide the USB data directory. >&2
    exit /b 1
)

rem ------------------------------------------------------------------------------
rem Phase 4: Concurrency lock and base logging
rem ------------------------------------------------------------------------------
if exist "%LOCK_FILE%" (
    echo [ERROR] [Launcher] Another 3A1shOnWin instance is already active. >&2
    exit /b 2
)
> "%LOCK_FILE%" echo locked
if not exist "%LOCK_FILE%" (
    echo [ERROR] [Launcher] Failed to create the execution lock file. >&2
    exit /b 1
)

> "%LOG_FILE%" echo [INFO] [Launcher] USB-STk started; host=%COMPUTERNAME%; user=%USERNAME%
if not exist "%LOG_FILE%" (
    echo [ERROR] [Launcher] Unable to create the launcher log file. >&2
    exit /b 1
)

>> "%AUDIT_FILE%" echo [AUDIT] [Launcher] USB project initialized at %PROJECT_ROOT%
if not exist "%AUDIT_FILE%" (
    echo [ERROR] [Launcher] Unable to create the audit file. >&2
    exit /b 1
)

rem ------------------------------------------------------------------------------
rem Phase 5: Dependency validation
rem ------------------------------------------------------------------------------
if not exist "%INFO_SCRIPT%" (
    >> "%LOG_FILE%" echo [ERROR] [Launcher] Missing info script: %INFO_SCRIPT%
    set "FINAL_RC=1"
    goto :cleanup
)

if not exist "%SSH_SCRIPT%" (
    >> "%LOG_FILE%" echo [ERROR] [Launcher] Missing SSH script: %SSH_SCRIPT%
    set "FINAL_RC=1"
    goto :cleanup
)

rem ------------------------------------------------------------------------------
rem Phase 6: Execute the modules in order
rem ------------------------------------------------------------------------------
start "" /b /wait powershell.exe -NoLogo -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File "%INFO_SCRIPT%" >> "%LOG_FILE%" 2>&1
set "INFO_RC=%ERRORLEVEL%"
>> "%LOG_FILE%" echo [INFO] [Launcher] info-3A1shOnWin.ps1 exit code: %INFO_RC%

rem The reconnaissance step runs first. The SSH step is executed after either a
rem success or failure result so that configuration is attempted only after the
rem environment has been inspected.
start "" /b /wait powershell.exe -NoLogo -NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File "%SSH_SCRIPT%" >> "%LOG_FILE%" 2>&1
set "SSH_RC=%ERRORLEVEL%"
>> "%LOG_FILE%" echo [INFO] [Launcher] ssh-3A1shOnWin.ps1 exit code: %SSH_RC%

if "%INFO_RC%"=="0" (
    set "FINAL_RC=0"
) else (
    set "FINAL_RC=%INFO_RC%"
)
if not "%SSH_RC%"=="0" if "%FINAL_RC%"=="0" set "FINAL_RC=%SSH_RC%"

:cleanup
if exist "%LOCK_FILE%" del /f /q "%LOCK_FILE%" 2>nul
if exist "%LOCK_FILE%" (
    echo [ERROR] [Launcher] Lock file could not be removed. >&2
    set "FINAL_RC=1"
)
>> "%LOG_FILE%" echo [INFO] [Launcher] Exiting with final code %FINAL_RC%
endlocal & exit /b %FINAL_RC%
