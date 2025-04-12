@echo off
echo WinIDS Network Monitor Runner
echo -------------------------------------

:: Check for admin rights
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Requesting administrator privileges...
    powershell -Command "Start-Process -FilePath '%~dpnx0' -Verb RunAs" -Wait
    exit /b
)

echo Running with administrator privileges.
echo Starting WinIDS Network Monitor with internet connectivity fix...
echo.

:: Run the network monitor module
python -m WinIDS.netmon

if %errorlevel% neq 0 (
    echo Error running network monitor!
    echo.
    echo Make sure the WinIDS package is properly installed.
    pause
)

exit /b 