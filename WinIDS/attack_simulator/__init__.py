"""
WinIDS Attack Simulator

This module provides attack simulation capabilities for the WinIDS package.
"""

from .base import simulate_attack, BaseAttackSimulator
from .dos import DOSAttackSimulator
from .probe import ProbeAttackSimulator
from .r2l import R2LAttackSimulator
from .u2r import U2RAttackSimulator

__all__ = [
    'simulate_attack',
    'BaseAttackSimulator',
    'DOSAttackSimulator',
    'ProbeAttackSimulator',
    'R2LAttackSimulator',
    'U2RAttackSimulator',
] 