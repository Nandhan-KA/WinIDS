"""
WinIDS Network Monitor Module

This module provides network monitoring and analysis capabilities for WinIDS using the Tkinter GUI.

Features:
- Real-time network traffic monitoring
- Protocol analysis and detection
- Application bandwidth tracking
- Geolocation of network connections
- Connection tracking and visualization

Command line usage:
- To launch the GUI: `python -m WinIDS.netmon`
"""

# Import directly from the local file
from .__main__ import main
from .network_analyzer_tkinter import NetworkAnalyzerGUI, main as tkinter_main
from .fix_network_monitor import fix_network_monitor

# Define what's available when using "from WinIDS.netmon import *"
__all__ = ['main', 'NetworkAnalyzerGUI', 'tkinter_main', 'fix_network_monitor']

# Version information
__version__ = '1.0.0' 