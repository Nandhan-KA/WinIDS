@echo off
echo WinIDS Network Analyzer Launcher
echo -------------------------------------
echo.

:: Check for admin rights
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo This tool requires administrator privileges.
    echo Requesting elevation...
    
    powershell -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

echo Running with administrator privileges
echo Starting Network Analyzer...
echo.

:: Run the network analyzer
python -m WinIDS.netmon

:: If there was an error, pause to show the message
if %errorlevel% neq 0 (
    echo.
    echo Error occurred while running the Network Analyzer.
    pause
) 