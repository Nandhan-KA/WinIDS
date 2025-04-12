@echo off
echo WinIDS Network Analyzer
echo -------------------------------------

:: Check for admin rights
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Requesting administrator privileges...
    powershell -Command "Start-Process -FilePath '%~dpnx0' -Verb RunAs" -Wait
    exit /b
)

echo Running with administrator privileges.
echo Starting WinIDS Network Analyzer with Geolocation...
echo.
echo The application will start monitoring automatically after launch.
echo If monitoring doesn't start automatically, use the START MONITORING button.
echo.

:: Run the network analyzer module directly
python -m WinIDS.netmon

if %errorlevel% neq 0 (
    echo Error running network analyzer!
    echo.
    echo Make sure the WinIDS package is properly installed.
    pause
)

exit /b 