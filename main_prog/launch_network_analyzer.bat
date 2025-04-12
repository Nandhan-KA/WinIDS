@echo off
echo WinIDS Network Analyzer (Enhanced Edition)
echo -------------------------------------

:: Check for admin rights
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Requesting administrator privileges...
    powershell -Command "Start-Process -FilePath '%~dpnx0' -Verb RunAs" -Wait
    exit /b
)

echo Running with administrator privileges.
echo Starting Enhanced Network Analyzer with Geolocation...
echo.
echo The application will start monitoring automatically after launch.
echo If monitoring doesn't start automatically, use the START MONITORING button.
echo.

:: Change to the correct directory
cd C:\Users\nandhanka\Desktop\ids
echo Current directory: %CD%
dir network_analyzer_tkinter.py

:: Check if GeoIP database exists, download if needed
if not exist "geoip_db\GeoLite2-City.mmdb" (
    echo GeoIP database not found. Downloading...
    python download_geoip_db.py
)

:: Run the network analyzer using Python from PATH
python C:\Users\nandhanka\Desktop\ids\network_analyzer_tkinter.py

if %errorlevel% neq 0 (
    echo Error running network analyzer!
    echo Current directory: %CD%
    echo Python path:
    where python
    echo.
    echo Make sure network_analyzer_tkinter.py exists in the correct location
    pause
)

exit /b 