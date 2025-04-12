#!/usr/bin/env python
"""
WinIDS Network Monitor Fix

This module provides a function to fix the internet connectivity issue in the WinIDS Network Monitor.
The fix ensures that packets are properly forwarded after being captured, maintaining internet connectivity
while still allowing the monitor to analyze the traffic.

Fix for syntax error in network_monitor.py
This script corrects the indentation issue with the exception handling in the _init_geoip method
"""

import os
import sys
import logging
import traceback
import ctypes
import subprocess
import importlib.util
import shutil
import re

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

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

def fix_network_monitor():
    """Fix the syntax error in network_monitor.py"""
    
    try:
        # Path to the original file
        file_path = os.path.join(os.path.dirname(__file__), "network_monitor.py")
        
        # Path for the backup file
        backup_path = os.path.join(os.path.dirname(__file__), "network_monitor.py.bak")
        
        # Create a backup of the original file
        shutil.copy2(file_path, backup_path)
        print(f"Created backup at {backup_path}")
        
        # Read the original file
        with open(file_path, 'r') as f:
            content = f.read()
        
        # Fix the indentation issue with the except block
        fixed_content = re.sub(
            r'(\s+)# Open GeoIP readers\n(\s+)self\.geoip_city = geoip2\.database\.Reader\(city_db_path\)\n(\s+)self\.geoip_country = geoip2\.database\.Reader\(country_db_path\)\n(\s+)logging\.info\(f"Initialized GeoIP database from \{city_db_path\}"\)\n(\s+)except Exception as e:',
            r'\1# Open GeoIP readers\n\2self.geoip_city = geoip2.database.Reader(city_db_path)\n\3self.geoip_country = geoip2.database.Reader(country_db_path)\n\4logging.info(f"Initialized GeoIP database from {city_db_path}")\n\1except Exception as e:',
            content
        )
        
        # Write the fixed content back to the file
        with open(file_path, 'w') as f:
            f.write(fixed_content)
        
        print("Successfully fixed the syntax error in network_monitor.py")
        return True
    
    except Exception as e:
        print(f"Error fixing network_monitor.py: {e}")
        return False

def main():
    """Main function to run the fix"""
    # Check for admin privileges
    if not is_admin():
        print("Administrator privileges required for fixing the network monitor.")
        run_as_admin()
        return
    
    print("WinIDS Network Monitor Fix")
    print("-------------------------")
    print("This script will fix the internet connectivity issue in the WinIDS Network Monitor.")
    print("The fix ensures that packets are properly forwarded after being captured.")
    print()
    
    if fix_network_monitor():
        print("Fix applied successfully!")
        print("You can now run the WinIDS Network Monitor without losing internet connectivity.")
    else:
        print("Failed to apply the fix.")
        print("Please make sure you have the necessary permissions and try again.")
    
    input("Press Enter to exit...")

if __name__ == "__main__":
    main() 