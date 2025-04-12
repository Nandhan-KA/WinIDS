#!/usr/bin/env python
"""
WinIDS Network Monitor Fix
This script fixes the internet connectivity issue in the WinIDS Network Monitor.
"""

import os
import sys
import logging
import traceback
import ctypes
import subprocess
import importlib.util

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
    """Fix the network monitor to maintain internet connectivity"""
    try:
        # Find the network_monitor.py file
        winids_path = None
        for path in sys.path:
            if os.path.exists(os.path.join(path, 'WinIDS', 'netmon', 'network_monitor.py')):
                winids_path = os.path.join(path, 'WinIDS', 'netmon', 'network_monitor.py')
                break
        
        if not winids_path:
            # Try to find it in the current directory
            if os.path.exists('WinIDS/netmon/network_monitor.py'):
                winids_path = 'WinIDS/netmon/network_monitor.py'
            else:
                logger.error("Could not find network_monitor.py file")
                return False
        
        logger.info(f"Found network_monitor.py at: {winids_path}")
        
        # Read the file
        with open(winids_path, 'r') as f:
            content = f.read()
        
        # Check if the fix is already applied
        if "w.send(packet)" in content:
            logger.info("Fix is already applied to the file")
            return True
        
        # Apply the fix
        fixed_content = content.replace(
            "packet = w.recv()\n                        self.packet_queue.put(packet)",
            "packet = w.recv()\n                        # Forward the packet to maintain internet connectivity\n                        w.send(packet)\n                        # Add to queue for analysis\n                        self.packet_queue.put(packet)"
        )
        
        # Write the fixed content back to the file
        with open(winids_path, 'w') as f:
            f.write(fixed_content)
        
        logger.info("Successfully applied fix to network_monitor.py")
        return True
        
    except Exception as e:
        logger.error(f"Error fixing network monitor: {e}")
        traceback.print_exc()
        return False

def main():
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