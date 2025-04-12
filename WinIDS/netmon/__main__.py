#!/usr/bin/env python
"""
WinIDS Network Analyzer - Main Entry Point
This file enables running the network analyzer as a module with the command:
python -m WinIDS.netmon
"""

import sys
import os
import traceback
import tkinter as tk
import ctypes
import subprocess
import importlib.util

def is_admin():
    """Check if the script is running with administrator privileges"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except:
        return False

def run_as_admin():
    """Restart the script with administrator privileges"""
    script = sys.executable
    # Use both lowercase and uppercase commands to ensure compatibility
    if "winids" in sys.argv[0].lower():
        # If running as installed package with lowercase name
        cmd = f'powershell -Command "Start-Process -FilePath \'{script}\' -ArgumentList \'-m winids.netmon\' -Verb RunAs"'
    else:
        # Default to uppercase module name
        cmd = f'powershell -Command "Start-Process -FilePath \'{script}\' -ArgumentList \'-m WinIDS.netmon\' -Verb RunAs"'
    
    print("Requesting administrator privileges...")
    subprocess.call(cmd, shell=True)
    sys.exit(0)

def initialize_geodb():
    """Initialize the GeoIP database before starting the application"""
    try:
        # Try importing from different module paths to ensure compatibility
        try:
            from winids.netmon.download_geoip_db import download_geolite2_db
        except ImportError:
            try:
                from WinIDS.netmon.download_geoip_db import download_geolite2_db
            except ImportError:
                from .download_geoip_db import download_geolite2_db
        
        print("Initializing GeoIP database...")
        city_db, country_db = download_geolite2_db()
        print(f"GeoIP initialization complete. Using databases:\n- {city_db}\n- {country_db}")
        return True
    except Exception as e:
        print(f"Warning: GeoIP database initialization failed: {e}")
        traceback.print_exc()
        return False

def apply_network_monitor_fix():
    """Apply the fix to the network monitor to maintain internet connectivity"""
    try:
        # Try importing from different module paths to ensure compatibility
        try:
            from winids.netmon.fix_network_monitor import fix_network_monitor
        except ImportError:
            try:
                from WinIDS.netmon.fix_network_monitor import fix_network_monitor
            except ImportError:
                from .fix_network_monitor import fix_network_monitor
        
        print("Applying network monitor fix to maintain internet connectivity...")
        if fix_network_monitor():
            print("Network monitor fix applied successfully!")
            return True
        else:
            print("Warning: Failed to apply network monitor fix.")
            print("Internet connectivity may be affected while using the network monitor.")
            return False
    except Exception as e:
        print(f"Warning: Network monitor fix failed: {e}")
        traceback.print_exc()
        return False

def main():
    # Check for admin privileges
    if not is_admin():
        print("Administrator privileges required for network monitoring.")
        run_as_admin()
        return
        
    try:
        print("Starting WinIDS Network Analyzer...")
        print(f"Python version: {sys.version}")
        print(f"Current directory: {os.getcwd()}")
        print("Running with administrator privileges.")
        
        # Initialize GeoIP database
        initialize_geodb()
        
        # Apply network monitor fix
        apply_network_monitor_fix()
        
        # Import and run the GUI application
        try:
            # Try with lowercase module name first (more likely to work)
            from winids.netmon.network_analyzer_tkinter import NetworkAnalyzerGUI
        except ImportError:
            # Fallback to uppercase if needed
            try:
                from WinIDS.netmon.network_analyzer_tkinter import NetworkAnalyzerGUI
            except ImportError:
                # Last resort - try relative import
                try:
                    from .network_analyzer_tkinter import NetworkAnalyzerGUI
                except ImportError:
                    print("Error: Could not import NetworkAnalyzerGUI. Make sure the package is properly installed.")
                    print("Try reinstalling the package with: pip install -e .")
                    return
        
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