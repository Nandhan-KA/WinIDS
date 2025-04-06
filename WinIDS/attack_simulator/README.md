# WinIDS Attack Simulator

This directory contains attack simulator modules for generating various types of attacks to test the IDS system.

## Available Attack Types

- DOS (Denial of Service)
- Probe (Network scanning and probing)
- R2L (Remote to Local attacks)
- U2R (User to Root attacks)

## Usage

The attack simulator is integrated with the WinIDS Attack Panel GUI and can be controlled through that interface. 
It can also be used programmatically as follows:

```python
from WinIDS.attack_simulator import simulate_attack

# Simulate a DOS attack with 75% intensity for 10 seconds
simulate_attack(attack_type="dos", intensity=0.75, duration=10)
```

## Creating Custom Attack Simulations

To create custom attack simulations, you can extend the base classes in this module:

```python
from WinIDS.attack_simulator.base import BaseAttackSimulator

class MyCustomAttack(BaseAttackSimulator):
    def __init__(self):
        super().__init__(attack_type="custom")
        
    def generate(self, intensity=0.5, duration=10):
        # Implementation for custom attack generation
        pass
```

## Disclaimer

The attack simulations provided in this package are intended for educational and testing purposes only.
Do not use these to attack systems without explicit permission. 