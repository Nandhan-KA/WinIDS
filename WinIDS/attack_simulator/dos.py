"""
DOS (Denial of Service) attack simulator
"""

import random
import time
import logging
from .base import BaseAttackSimulator

logger = logging.getLogger("WinIDS-DOSAttackSimulator")

class DOSAttackSimulator(BaseAttackSimulator):
    """Simulator for DOS (Denial of Service) attacks"""
    
    def __init__(self):
        """Initialize the DOS attack simulator"""
        super().__init__(attack_type="dos")
        
        # DOS attack characteristics
        self.characteristics = {
            "high_packet_rate": True,
            "repetitive_patterns": True,
            "large_packet_size": True,
            "connection_flood": True
        }
        
    def generate(self, intensity=0.5, duration=10):
        """Generate DOS attack traffic
        
        Args:
            intensity (float): Attack intensity from 0.1 to 1.0
            duration (int): Duration of attack in seconds
            
        Returns:
            list: Generated attack traffic data
        """
        # Validate parameters
        intensity, duration = self._validate_params(intensity, duration)
        
        # Determine number of packets to generate
        packet_count = self._generate_packet_count(intensity, duration)
        
        logger.info(f"Generating DOS attack with {packet_count} packets (intensity: {intensity}, duration: {duration}s)")
        
        # Generate attack packets
        packets = []
        
        # DOS attack feature patterns
        # Higher values for network throughput features
        # Lower values for connection duration (many short connections)
        for i in range(packet_count):
            # Base features (20 features)
            features = [0.0] * 20
            
            # Set typical DOS attack patterns in features
            # Features 0-3: Network throughput metrics (high for DOS)
            features[0] = random.uniform(0.7, 1.0) * intensity  # Packet rate
            features[1] = random.uniform(0.8, 1.0) * intensity  # Byte rate
            features[2] = random.uniform(0.7, 0.9) * intensity  # Packet size
            features[3] = random.uniform(0.8, 1.0) * intensity  # Flow volume
            
            # Features 4-6: Connection characteristics
            features[4] = random.uniform(0.0, 0.3) * (1 - intensity)  # Connection duration (low)
            features[5] = random.uniform(0.7, 1.0) * intensity  # Connection frequency
            features[6] = random.uniform(0.7, 1.0) * intensity  # Connection repetition
            
            # Features 7-10: Protocol characteristics
            features[7] = random.uniform(0.6, 1.0) if random.random() < 0.7 else 0  # TCP flags (SYN floods)
            features[8] = random.uniform(0.0, 0.3)  # Protocol diversity (low)
            features[9] = random.uniform(0.8, 1.0) * intensity  # Protocol anomaly
            features[10] = random.uniform(0.7, 1.0) * intensity if random.random() < 0.8 else 0  # ICMP traffic
            
            # Features 11-14: Target characteristics
            features[11] = random.uniform(0.0, 0.3)  # Target IP diversity (low - focused attack)
            features[12] = random.uniform(0.7, 1.0) * intensity  # Target port concentration
            features[13] = random.uniform(0.0, 0.3)  # Target service diversity (low)
            features[14] = random.uniform(0.5, 1.0) * intensity  # Server load indicator
            
            # Features 15-19: Time-based characteristics
            features[15] = random.uniform(0.7, 1.0) * intensity  # Traffic regularity (high)
            features[16] = random.uniform(0.8, 1.0) * intensity  # Burst intensity
            features[17] = random.uniform(0.0, 0.3)  # Time between connections (low)
            features[18] = random.uniform(0.7, 1.0) * intensity  # Persistence indicator
            features[19] = random.uniform(0.7, 1.0) * intensity if random.random() < 0.9 else 0  # Time pattern anomaly
            
            # Add randomness based on inverse of intensity
            randomness = (1.0 - intensity) * 0.3
            features = [max(0, min(1, f + random.uniform(-randomness, randomness))) for f in features]
            
            # Create packet data
            packet = {
                "type": "traffic",
                "attack_type": "dos",
                "features": features,
                "intensity": intensity,
                "synthetic": True,
                "timestamp": time.time()
            }
            
            packets.append(packet)
        
        return packets 