@echo off
echo WinIDS Network Monitor Fix
echo -------------------------------------

:: Check for admin rights
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Requesting administrator privileges...
    powershell -Command "Start-Process -FilePath '%~dpnx0' -Verb RunAs" -Wait
    exit /b
)

echo Running with administrator privileges.
echo Applying fix to network monitor...
echo.

:: Run the fix script
python fix_network_monitor.py

if %errorlevel% neq 0 (
    echo Error running fix script!
    echo.
    echo Make sure Python is properly installed.
    pause
)

exit /b 