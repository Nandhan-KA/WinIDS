#!/usr/bin/env python
"""
Direct Launcher for WinIDS Network Analyzer

This is a direct launcher script that imports and runs the network analyzer
without going through the module system. This can sometimes resolve import path issues.
"""

import os
import sys
import ctypes
import traceback

def is_admin():
    """Check if running with administrator privileges"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception as e:
        print(f"Error checking admin status: {e}")
        return False

def request_admin():
    """Restart this script with admin rights"""
    try:
        script_path = os.path.abspath(__file__)
        print(f"Requesting admin privileges for: {script_path}")
        
        # Request elevation
        ctypes.windll.shell32.ShellExecuteW(
            None, 
            "runas", 
            sys.executable, 
            f'"{script_path}"', 
            None, 
            1
        )
    except Exception as e:
        print(f"Error requesting admin rights: {e}")
        traceback.print_exc()

def main():
    """Main entry point for the launcher"""
    try:
        print("Direct Launcher for WinIDS Network Analyzer")
        print("===========================================")
        print(f"Python version: {sys.version}")
        print(f"Current directory: {os.getcwd()}")
        print(f"Script location: {os.path.abspath(__file__)}")
        
        # Check for admin privileges
        if not is_admin():
            print("Administrator privileges are required.")
            input("Press Enter to request admin privileges...")
            request_admin()
            return
        
        print("Running with administrator privileges")
        
        # Add the parent directory to sys.path for imports
        sys_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        if sys_path not in sys.path:
            sys.path.insert(0, sys_path)
            print(f"Added to sys.path: {sys_path}")
        
        # Import the network analyzer GUI
        print("Importing WinIDS network analyzer...")
        try:
            from WinIDS.netmon.network_analyzer_gui import main as gui_main
            print("Successfully imported network analyzer.")
            
            # Run the network analyzer
            print("Starting network analyzer...")
            gui_main()
            
        except ImportError as e:
            print(f"Error importing network analyzer: {e}")
            print("\nTry running the diagnostic script to check all dependencies:")
            print("python -m WinIDS.netmon.diagnose")
            traceback.print_exc()
            input("Press Enter to exit...")
            
    except Exception as e:
        print(f"Error in launcher: {e}")
        traceback.print_exc()
        input("Press Enter to exit...")

if __name__ == "__main__":
    main() 