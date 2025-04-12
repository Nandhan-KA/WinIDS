@echo off
echo WinIDS Network Monitor Fix Test
echo -------------------------------------

:: Check for admin rights
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Requesting administrator privileges...
    powershell -Command "Start-Process -FilePath '%~dpnx0' -Verb RunAs" -Wait
    exit /b
)

echo Running with administrator privileges.
echo Testing network monitor fix...
echo.

:: Run the test script
python test_netmon_fix.py

if %errorlevel% neq 0 (
    echo Error running test script!
    echo.
    echo Make sure Python and pydivert are properly installed.
    pause
)

exit /b 