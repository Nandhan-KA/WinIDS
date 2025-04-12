"""
MacIDS - macOS Intrusion Detection System
"""

import logging
import os
import sys
import platform

# Check for macOS
if platform.system() != "Darwin":
    print("Warning: MacIDS is designed for macOS systems.")
    print(f"Current system detected: {platform.system()}")
    print("Some functionality may not work correctly.")

# Set up package-wide logging
LOG_FORMAT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
logging.basicConfig(
    level=logging.INFO,
    format=LOG_FORMAT,
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler("macids.log")
    ]
)

# Package metadata
__version__ = "1.2"
__author__ = "Nandhan K"
__email__ = "developer.nandhank@gmail.com"
__description__ = "macOS Intrusion Detection System"

# Define package components
__all__ = ["netmon"]

logger = logging.getLogger("macids")
logger.info(f"MacIDS v{__version__} initializing...")
logger.info(f"Running on {platform.system()} {platform.release()} ({platform.version()})")

def get_package_dir():
    """Return the root directory of the package."""
    return os.path.dirname(os.path.abspath(__file__))

def is_admin():
    """Check if the current process has admin privileges."""
    try:
        if platform.system() == "Darwin":
            return os.geteuid() == 0
        return False
    except:
        return False 