"""
Base classes and functions for attack simulation
"""

import random
import logging
import importlib
from abc import ABC, abstractmethod

# Configure logging
logger = logging.getLogger("WinIDS-AttackSimulator")

class BaseAttackSimulator(ABC):
    """Base class for all attack simulators"""
    
    def __init__(self, attack_type):
        """Initialize the attack simulator
        
        Args:
            attack_type (str): Type of attack ("dos", "probe", "r2l", "u2r")
        """
        self.attack_type = attack_type
    
    @abstractmethod
    def generate(self, intensity=0.5, duration=10):
        """Generate attack traffic
        
        Args:
            intensity (float): Attack intensity from 0.1 to 1.0
            duration (int): Duration of attack in seconds
            
        Returns:
            list: Generated attack traffic data
        """
        pass
    
    def _validate_params(self, intensity, duration):
        """Validate attack parameters
        
        Args:
            intensity (float): Attack intensity
            duration (int): Attack duration
            
        Returns:
            tuple: Validated (intensity, duration)
        """
        # Ensure intensity is between 0.1 and 1.0
        intensity = max(0.1, min(1.0, intensity))
        
        # Ensure duration is at least 1 second
        duration = max(1, int(duration))
        
        return intensity, duration
        
    def _generate_packet_count(self, intensity, duration):
        """Calculate number of packets to generate based on intensity
        
        Args:
            intensity (float): Attack intensity
            duration (int): Attack duration
            
        Returns:
            int: Number of packets to generate
        """
        # Base number of packets per second
        base_packets = 10
        
        # Calculate packets based on intensity (exponential relationship)
        packets_per_second = base_packets * (10 ** (intensity * 2))
        
        # Total packets for the duration
        total_packets = int(packets_per_second * duration)
        
        # Cap at a reasonable maximum
        return min(total_packets, 1000000)

def simulate_attack(attack_type="dos", intensity=0.5, duration=10):
    """Simulate an attack of the specified type
    
    Args:
        attack_type (str): Type of attack ("dos", "probe", "r2l", "u2r")
        intensity (float): Attack intensity from 0.1 to 1.0
        duration (int): Duration of attack in seconds
        
    Returns:
        list: Generated attack traffic data
        
    Raises:
        ValueError: If attack_type is invalid
    """
    # Normalize attack type to lowercase
    attack_type = attack_type.lower()
    
    # Validate attack type
    valid_types = ["dos", "probe", "r2l", "u2r"]
    if attack_type not in valid_types:
        raise ValueError(f"Invalid attack type: {attack_type}. Valid types are: {', '.join(valid_types)}")
    
    # Import the appropriate simulator class
    try:
        module_name = f".{attack_type}"
        module = importlib.import_module(module_name, package="WinIDS.attack_simulator")
        
        # Construct class name
        class_name = f"{attack_type.upper()}AttackSimulator"
        if attack_type == "r2l":
            class_name = "R2LAttackSimulator"
        elif attack_type == "u2r":
            class_name = "U2RAttackSimulator"
            
        # Get class from module
        simulator_class = getattr(module, class_name)
        
        # Create instance and generate attack
        simulator = simulator_class()
        return simulator.generate(intensity, duration)
        
    except (ImportError, AttributeError) as e:
        logger.error(f"Error loading attack simulator for {attack_type}: {str(e)}")
        
        # Use fallback generic implementation
        logger.info(f"Using fallback generic attack simulation for {attack_type}")
        
        # Create a generic attack pattern
        packets = []
        packet_count = int(100 * intensity * duration)
        
        for i in range(packet_count):
            packet = {
                "type": "attack",
                "attack_type": attack_type,
                "features": [random.random() for _ in range(20)],
                "intensity": intensity,
                "synthetic": True
            }
            packets.append(packet)
        
        return packets 