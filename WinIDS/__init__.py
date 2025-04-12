"""
WinIDS - Windows Intrusion Detection System

A machine learning and reinforcement learning-based intrusion detection system 
designed for Windows environments with real-time monitoring capabilities.
"""

__version__ = "1.2"
__author__ = "Nandhan K"

# Import main components
from .fast_run import FastIDS
from .pro_dashboard import ProDashboard
from .bridge import IDSBridge
from .monitor import IDSMonitor
from .attack_panel import AttackPanel

# Import RL components (if available)
try:
    from .rl_agent import AdaptiveIDS, DQNAgent, RLEnvironment
    RL_AVAILABLE = True
except ImportError:
    RL_AVAILABLE = False

# Provide simplified access to key functionality
__all__ = [
    "FastIDS",
    "ProDashboard", 
    "IDSBridge",
    "IDSMonitor",
    "AttackPanel",
    "run_dashboard",
    "run_bridge",
    "run_monitor",
    "run_attack_panel"
]

# Add RL components to __all__ if available
if RL_AVAILABLE:
    __all__.extend(["AdaptiveIDS", "DQNAgent", "RLEnvironment", "RL_AVAILABLE"])
else:
    __all__.append("RL_AVAILABLE")

def run_dashboard():
    """Run the WinIDS dashboard application."""
    from .pro_dashboard import main
    return main()

def run_bridge():
    """Run the WinIDS bridge component."""
    from .bridge import main
    return main()

def run_monitor():
    """Run the WinIDS monitor component."""
    from .monitor import main
    return main()

def run_attack_panel():
    """Run the WinIDS attack panel application."""
    from .attack_panel import main
    return main() 