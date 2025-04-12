"""
Main entry point for MacIDS when run as a module (python -m macids)
"""

import sys
import os
import argparse
import logging
from . import __version__, is_admin

logger = logging.getLogger("macids")

def main():
    """Main entry point for MacIDS"""
    # Check for admin privileges
    if not is_admin():
        print("Warning: MacIDS requires administrator privileges for full functionality.")
        print("Some features may not work correctly.")
        print("Please run with 'sudo' for complete functionality.")
    
    # Set up argument parser
    parser = argparse.ArgumentParser(description=f"MacIDS v{__version__} - macOS Intrusion Detection System")
    parser.add_argument("--version", action="version", version=f"MacIDS v{__version__}")
    parser.add_argument("--netmon", action="store_true", help="Launch the network monitor")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    
    args = parser.parse_args()
    
    # Set debug logging if requested
    if args.debug:
        logging.getLogger("macids").setLevel(logging.DEBUG)
        logger.debug("Debug logging enabled")
    
    # Determine what component to launch
    if args.netmon:
        logger.info("Launching Network Monitor")
        from .netmon.__main__ import main as netmon_main
        return netmon_main()
    else:
        # Default to network monitor for now
        logger.info("No specific component selected, defaulting to Network Monitor")
        from .netmon.__main__ import main as netmon_main
        return netmon_main()

if __name__ == "__main__":
    sys.exit(main()) 