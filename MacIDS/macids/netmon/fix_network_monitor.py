#!/usr/bin/env python
"""
MacIDS Network Monitor Fix

This module provides a function to fix potential syntax issues in the MacIDS Network Monitor.
The script checks for proper indentation in exception handling blocks and fixes them if needed.
"""

import os
import sys
import logging
import traceback
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

def check_admin():
    """Check if the script is running with appropriate permissions"""
    try:
        # On macOS, we need to check if we can write to the file
        file_path = os.path.join(os.path.dirname(__file__), "network_monitor.py")
        return os.access(file_path, os.W_OK)
    except:
        return False

def request_sudo():
    """Request sudo access to run the script"""
    script = os.path.abspath(__file__)
    cmd = f'osascript -e "do shell script \\"python3 {script}\\" with administrator privileges"'
    
    print("Requesting administrator privileges...")
    subprocess.call(cmd, shell=True)
    sys.exit(0)

def fix_network_monitor():
    """Fix syntax issues in network_monitor.py"""
    
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
        
        # Fix the indentation issue with the except block (if it exists)
        fixed_content = re.sub(
            r'(\s+)# Open GeoIP readers\n(\s+)self\.geoip_city = geoip2\.database\.Reader\(city_db_path\)\n(\s+)self\.geoip_country = geoip2\.database\.Reader\(country_db_path\)\n(\s+)logging\.info\(f"Initialized GeoIP database from \{city_db_path\}"\)\n(\s+)except Exception as e:',
            r'\1# Open GeoIP readers\n\2self.geoip_city = geoip2.database.Reader(city_db_path)\n\3self.geoip_country = geoip2.database.Reader(country_db_path)\n\4logging.info(f"Initialized GeoIP database from {city_db_path}")\n\1except Exception as e:',
            content
        )
        
        # Check if any changes were made
        if fixed_content == content:
            print("No syntax issues were found in network_monitor.py")
            return True
        
        # Write the fixed content back to the file
        with open(file_path, 'w') as f:
            f.write(fixed_content)
        
        print("Successfully fixed syntax issues in network_monitor.py")
        return True
    
    except Exception as e:
        print(f"Error fixing network_monitor.py: {e}")
        traceback.print_exc()
        return False

def main():
    """Main function to run the fix"""
    # Check for admin privileges
    if not check_admin():
        print("Administrator privileges required for fixing the network monitor.")
        request_sudo()
        return
    
    print("MacIDS Network Monitor Fix")
    print("-------------------------")
    print("This script will check for syntax issues in the MacIDS Network Monitor.")
    print()
    
    if fix_network_monitor():
        print("Fix process completed successfully!")
        print("You can now run the MacIDS Network Monitor without syntax errors.")
    else:
        print("Failed to apply fixes.")
        print("Please make sure you have the necessary permissions and try again.")
    
    input("Press Enter to exit...")

if __name__ == "__main__":
    main() 