#!/usr/bin/env python
"""
WinIDS Network Analyzer - Diagnostic Tool

This script checks for all required dependencies and permissions
needed to run the WinIDS Network Analyzer.
"""

import os
import sys
import ctypes
import importlib
import subprocess
import platform

def check_admin():
    """Check if running with administrator privileges"""
    try:
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
        return is_admin
    except Exception as e:
        print(f"Error checking admin status: {e}")
        return False

def check_module(module_name):
    """Check if a module can be imported"""
    try:
        importlib.import_module(module_name)
        return True
    except ImportError as e:
        print(f"Error importing {module_name}: {e}")
        return False
    except Exception as e:
        print(f"Unexpected error importing {module_name}: {e}")
        return False

def check_network_capture():
    """Check if pydivert can be initialized"""
    try:
        import pydivert
        try:
            # Just try to initialize without starting capture
            with pydivert.WinDivert("false") as _:
                pass
            return True
        except Exception as e:
            print(f"Error initializing WinDivert: {e}")
            return False
    except ImportError:
        print("Could not import pydivert")
        return False

def main():
    """Run diagnostic checks"""
    print("WinIDS Network Analyzer Diagnostic Tool")
    print("=======================================")
    print(f"Python version: {sys.version}")
    print(f"OS: {platform.platform()}")
    print(f"Current directory: {os.getcwd()}")
    print(f"Script location: {os.path.abspath(__file__)}")
    print("=======================================")
    
    # Check if running as administrator
    is_admin = check_admin()
    print(f"Running as administrator: {'Yes' if is_admin else 'No'}")
    
    if not is_admin:
        print("WARNING: Administrator privileges are required for network capturing")
    
    # Check required modules
    required_modules = [
        "tkinter", "matplotlib", "numpy", "pandas", 
        "pydivert", "psutil", "dns", "geoip2",
        "socket", "threading", "queue", "requests"
    ]
    
    print("\nChecking required modules:")
    all_modules_available = True
    for module in required_modules:
        result = check_module(module)
        print(f"  {module}: {'OK' if result else 'FAILED'}")
        if not result:
            all_modules_available = False
    
    # Check pydivert capture capability
    print("\nChecking network capture capability:")
    capture_ok = check_network_capture()
    print(f"  WinDivert initialization: {'OK' if capture_ok else 'FAILED'}")
    
    print("\nSummary:")
    if is_admin and all_modules_available and capture_ok:
        print("All checks passed. The Network Analyzer should work correctly.")
    else:
        print("Some checks failed. The Network Analyzer may not work correctly.")
        
        if not is_admin:
            print("  - Please run this script as Administrator")
        if not all_modules_available:
            print("  - Install missing Python modules with: pip install <module_name>")
        if not capture_ok:
            print("  - Make sure WinDivert is properly installed and compatible with your OS")
    
    input("\nPress Enter to exit...")

if __name__ == "__main__":
    main() 