"""
WinIDS Scripts

This package contains utility scripts for the WinIDS system.
"""

__all__ = ["train_model"]

# This module provides access to script functions as a Python API
from . import train_model

# Additional documentation about reinforcement learning
"""
Reinforcement Learning in WinIDS

The WinIDS system includes reinforcement learning capabilities for adaptive
intrusion detection. The RL components learn from experience to optimize:

1. Detection thresholds
2. Alert sensitivity
3. False positive reduction

For examples on using the reinforcement learning capabilities, see:
- examples/adaptive_ids_example.py
- scripts/run_adaptive_ids.bat (Windows)
- scripts/run_adaptive_ids.sh (Linux/macOS)
""" 