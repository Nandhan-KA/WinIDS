@echo off
echo Installing WinIDS package in development mode...
echo -------------------------------------

pip install -e .

if %errorlevel% neq 0 (
    echo Error installing WinIDS package!
    echo Python path:
    where python
    echo.
    pause
) else (
    echo WinIDS package installed successfully in development mode.
    echo You can now run "winids.netmon" or use the batch file "winids_netmon.bat"
)

pause 