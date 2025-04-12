"""
Main entry point for MacIDS Network Monitor when run as a module (python -m MacIDS.netmon)
"""

import sys
import os
import platform
import tkinter as tk
import argparse
import logging
import time
from .. import is_admin, __version__

logger = logging.getLogger("MacIDS.netmon")

def start_gui():
    """Launch the graphical interface for network monitoring"""
    try:
        # Import here to avoid circular imports
        try:
            # Try uppercase import first (user's intended path)
            from .network_analyzer_tkinter import NetworkAnalyzerGUI
        except ImportError:
            # Fallback to different import paths if needed
            try:
                from MacIDS.netmon.network_analyzer_tkinter import NetworkAnalyzerGUI
            except ImportError:
                from macids.netmon.network_analyzer_tkinter import NetworkAnalyzerGUI
        
        # Create main window
        root = tk.Tk()
        app = NetworkAnalyzerGUI(root)
        
        # Auto-start monitoring after a short delay if admin
        if is_admin():
            logger.info("Auto-starting network monitoring with admin privileges")
            root.after(2000, app.start_monitoring)
        else:
            logger.warning("Not running with admin privileges, some features may not work")
        
        # Start the main loop
        root.mainloop()
        
        return 0
    except Exception as e:
        logger.error(f"Error starting GUI: {e}")
        import traceback
        traceback.print_exc()
        return 1

def start_cli(args):
    """Start command-line monitoring"""
    try:
        # Import monitor
        from .network_monitor import SystemNetworkMonitor
        
        print(f"MacIDS Network Monitor v{__version__}")
        print("Starting system-wide network monitoring")
        print("Press Ctrl+C to stop")
        
        # Create monitor and start it
        monitor = SystemNetworkMonitor()
        if monitor.start_capture():
            print("Monitoring started successfully")
            
            # Wait until interrupted
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                print("\nMonitoring stopped by user")
            finally:
                monitor.stop_capture()
                print("Monitoring stopped")
                
            return 0
        else:
            print("Failed to start monitoring")
            return 1
    except Exception as e:
        logger.error(f"Error in CLI mode: {e}")
        import traceback
        traceback.print_exc()
        return 1

def main():
    """Main entry point for MacIDS Network Monitor"""
    # Check for macOS
    if platform.system() != "Darwin":
        print(f"Warning: This tool is designed for macOS but detected {platform.system()}")
        print("Some features may not work correctly on this platform")
    
    # Check for admin privileges
    if not is_admin():
        print("Warning: Network monitoring requires administrator privileges")
        print("Please run with 'sudo' for complete functionality")
    
    # Parse arguments
    parser = argparse.ArgumentParser(description=f"MacIDS Network Monitor v{__version__}")
    parser.add_argument("--cli", action="store_true", help="Run in command-line mode (no GUI)")
    parser.add_argument("--debug", action="store_true", help="Enable debug logging")
    args = parser.parse_args()
    
    # Set debug logging if requested
    if args.debug:
        logging.getLogger("macids").setLevel(logging.DEBUG)
        logging.getLogger("macids.netmon").setLevel(logging.DEBUG)
        logger.debug("Debug logging enabled")
    
    # Start in appropriate mode
    if args.cli:
        return start_cli(args)
    else:
        return start_gui()

if __name__ == "__main__":
    sys.exit(main()) 