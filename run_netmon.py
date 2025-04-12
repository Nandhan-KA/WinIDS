#!/usr/bin/env python
"""
WinIDS Network Monitor Runner

This script runs the WinIDS Network Monitor with the internet connectivity fix applied.
"""

import sys
import os
import subprocess
import ctypes

def is_admin():
    """Check if the script is running with administrator privileges"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except:
        return False

def run_as_admin():
    """Restart the script with administrator privileges"""
    script = os.path.abspath(__file__)
    cmd = f'powershell -Command "Start-Process -FilePath \'{sys.executable}\' -ArgumentList \'{script}\' -Verb RunAs"'
    
    print("Requesting administrator privileges...")
    subprocess.call(cmd, shell=True)
    sys.exit(0)

def main():
    # Check for admin privileges
    if not is_admin():
        print("Administrator privileges required for network monitoring.")
        run_as_admin()
        return
    
    print("WinIDS Network Monitor Runner")
    print("-----------------------------")
    print("This script will run the WinIDS Network Monitor with the internet connectivity fix applied.")
    print()
    
    # Run the network monitor module
    print("Starting WinIDS Network Monitor...")
    subprocess.call([sys.executable, "-m", "WinIDS.netmon"])
    
    print("Network Monitor has exited.")
    input("Press Enter to exit...")

if __name__ == "__main__":
    main() 