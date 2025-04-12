"""
MacIDS Network Monitor Package
Provides network traffic monitoring and analysis functionality for macOS.

This package can be run as a module with:
    python -m MacIDS.netmon  (preferred, capitalized)
    python -m macids.netmon  (alternative, lowercase)
"""

__version__ = "1.0.0"

# Import key components for easier access
from .network_monitor import SystemNetworkMonitor

# When used as a module, automatically run the main entry point
def run():
    """Helper function to run the network monitor"""
    from .__main__ import main
    return main()

import logging
import platform
import os

# Create module logger
logger = logging.getLogger("macids.netmon")

# Import checks
try:
    import scapy.all
    logger.info("Scapy imported successfully")
except ImportError as e:
    logger.error(f"Failed to import Scapy: {e}")
    logger.error("Network monitoring will not function without Scapy")

# Check for macOS and admin privileges
if platform.system() != "Darwin":
    logger.warning(f"MacIDS netmon is designed for macOS, detected: {platform.system()}")

if os.geteuid() != 0:
    logger.warning("Network monitoring requires root privileges to capture packets")
    logger.warning("Run this application with 'sudo' to enable all functionality")

__all__ = ["network_monitor", "network_analyzer_tkinter", "download_geoip_db"] 