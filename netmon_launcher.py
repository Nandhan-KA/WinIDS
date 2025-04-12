#!/usr/bin/env python
"""
WinIDS Network Analyzer Launcher
This script launches the network analyzer component directly.
"""

import sys
import os
import tkinter as tk
import traceback
import ctypes
import subprocess

def is_admin():
    """Check if the script is running with administrator privileges"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except:
        return False

def run_as_admin():
    """Restart the script with administrator privileges"""
    script = os.path.abspath(__file__)
    params = ' '.join(sys.argv[1:])
    cmd = f'powershell -Command "Start-Process -FilePath \'{sys.executable}\' -ArgumentList \'{script} {params}\' -Verb RunAs"'
    
    print("Requesting administrator privileges...")
    subprocess.call(cmd, shell=True)
    sys.exit(0)

def main():
    # Check for admin privileges
    if not is_admin():
        print("Administrator privileges required.")
        run_as_admin()
        return
        
    try:
        print("Starting WinIDS Network Analyzer...")
        print(f"Python version: {sys.version}")
        print(f"Current directory: {os.getcwd()}")
        print("Running with administrator privileges.")
        
        # Import GUI from the package
        from WinIDS.netmon.network_analyzer_tkinter import NetworkAnalyzerGUI
        
        # Create Tkinter root window
        root = tk.Tk()
        
        # Create the GUI application
        app = NetworkAnalyzerGUI(root)
        
        # Auto-start monitoring after a short delay
        print("Auto-starting network monitoring in 2 seconds...")
        root.after(2000, app.start_monitoring)
        
        # Start the Tkinter event loop
        root.mainloop()
        
    except Exception as e:
        print(f"Error in WinIDS Network Analyzer: {e}")
        traceback.print_exc()
        input("Press Enter to exit...")

if __name__ == "__main__":
    main() 