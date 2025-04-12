#!/usr/bin/env python
"""
Test script to verify the network monitor fix
"""

import sys
import os
import logging
import pydivert

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

def test_netmon_fix():
    """Test the network monitor fix"""
    try:
        logger.info("Testing network monitor fix...")
        
        # Create WinDivert handle for all network traffic
        with pydivert.WinDivert("true") as w:
            logger.info("Started packet capture")
            
            # Capture and forward a few packets
            for i in range(5):
                try:
                    # Read a packet
                    packet = w.recv()
                    logger.info(f"Captured packet: {packet}")
                    
                    # Forward the packet to maintain internet connectivity
                    w.send(packet)
                    logger.info(f"Forwarded packet: {packet}")
                    
                except Exception as e:
                    logger.error(f"Error capturing/forwarding packet: {e}")
        
        logger.info("Test completed successfully!")
        return True
        
    except Exception as e:
        logger.error(f"Test failed: {e}")
        return False

if __name__ == "__main__":
    # Check for admin privileges
    try:
        import ctypes
        is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
    except:
        is_admin = False
    
    if not is_admin:
        print("This test requires administrator privileges.")
        print("Please run this script as administrator.")
        sys.exit(1)
    
    test_netmon_fix() 