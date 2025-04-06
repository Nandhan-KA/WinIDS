"""
R2L (Remote to Local) attack simulator
"""

import random
import time
import logging
from .base import BaseAttackSimulator

logger = logging.getLogger("WinIDS-R2LAttackSimulator")

class R2LAttackSimulator(BaseAttackSimulator):
    """Simulator for R2L (Remote to Local) attacks"""
    
    def __init__(self):
        """Initialize the R2L attack simulator"""
        super().__init__(attack_type="r2l")
        
        # R2L attack characteristics
        self.characteristics = {
            "unauthorized_access": True,
            "credential_exploitation": True,
            "focused_targets": True,
            "low_volume_traffic": True
        }
        
    def generate(self, intensity=0.5, duration=10):
        """Generate R2L attack traffic
        
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
        
        # R2L attacks typically have much fewer packets than DOS
        packet_count = int(packet_count * 0.05)
        
        logger.info(f"Generating R2L attack with {packet_count} packets (intensity: {intensity}, duration: {duration}s)")
        
        # Generate attack packets
        packets = []
        
        # R2L attack feature patterns
        for i in range(packet_count):
            # Base features (20 features)
            features = [0.0] * 20
            
            # Set typical R2L attack patterns in features
            # Features 0-3: Network throughput metrics (very low for R2L)
            features[0] = random.uniform(0.1, 0.3) * intensity  # Packet rate
            features[1] = random.uniform(0.1, 0.3) * intensity  # Byte rate
            features[2] = random.uniform(0.2, 0.4) * intensity  # Packet size
            features[3] = random.uniform(0.1, 0.3) * intensity  # Flow volume
            
            # Features 4-6: Connection characteristics
            features[4] = random.uniform(0.5, 0.8) * intensity  # Connection duration (medium-high)
            features[5] = random.uniform(0.1, 0.3) * intensity  # Connection frequency (low)
            features[6] = random.uniform(0.3, 0.6) * intensity  # Connection repetition (medium)
            
            # Features 7-10: Protocol characteristics
            features[7] = random.uniform(0.3, 0.6) * intensity if random.random() < 0.4 else 0  # TCP flags
            features[8] = random.uniform(0.2, 0.4) * intensity  # Protocol diversity (low)
            features[9] = random.uniform(0.5, 0.8) * intensity  # Protocol anomaly (medium-high)
            features[10] = random.uniform(0.0, 0.2) * intensity  # ICMP traffic (very low)
            
            # Features 11-14: Target characteristics
            features[11] = random.uniform(0.0, 0.3) * intensity  # Target IP diversity (very low - focused)
            features[12] = random.uniform(0.3, 0.6) * intensity  # Target port diversity (medium)
            features[13] = random.uniform(0.1, 0.4) * intensity  # Target service diversity (low)
            features[14] = random.uniform(0.1, 0.3) * intensity  # Server load indicator (low)
            
            # Features 15-19: Time-based characteristics
            features[15] = random.uniform(0.2, 0.5) * intensity  # Traffic regularity (low-medium)
            features[16] = random.uniform(0.1, 0.3) * intensity  # Burst intensity (low)
            features[17] = random.uniform(0.5, 0.8) * intensity  # Time between connections (high)
            features[18] = random.uniform(0.6, 0.9) * intensity  # Persistence indicator (high)
            features[19] = random.uniform(0.5, 0.8) * intensity if random.random() < 0.6 else 0  # Time pattern anomaly
            
            # Add randomness based on inverse of intensity
            randomness = (1.0 - intensity) * 0.3
            features = [max(0, min(1, f + random.uniform(-randomness, randomness))) for f in features]
            
            # Create packet data
            packet = {
                "type": "traffic",
                "attack_type": "r2l",
                "features": features,
                "intensity": intensity,
                "synthetic": True,
                "timestamp": time.time()
            }
            
            packets.append(packet)
        
        return packets 