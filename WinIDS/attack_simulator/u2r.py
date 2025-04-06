"""
U2R (User to Root) attack simulator
"""

import random
import time
import logging
from .base import BaseAttackSimulator

logger = logging.getLogger("WinIDS-U2RAttackSimulator")

class U2RAttackSimulator(BaseAttackSimulator):
    """Simulator for U2R (User to Root) attacks"""
    
    def __init__(self):
        """Initialize the U2R attack simulator"""
        super().__init__(attack_type="u2r")
        
        # U2R attack characteristics
        self.characteristics = {
            "privilege_escalation": True,
            "exploit_execution": True,
            "very_low_volume": True,
            "long_connection_times": True
        }
        
    def generate(self, intensity=0.5, duration=10):
        """Generate U2R attack traffic
        
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
        
        # U2R attacks typically have extremely few packets
        packet_count = int(packet_count * 0.02)
        
        # Ensure at least a few packets
        packet_count = max(packet_count, 5)
        
        logger.info(f"Generating U2R attack with {packet_count} packets (intensity: {intensity}, duration: {duration}s)")
        
        # Generate attack packets
        packets = []
        
        # U2R attack feature patterns
        for i in range(packet_count):
            # Base features (20 features)
            features = [0.0] * 20
            
            # Set typical U2R attack patterns in features
            # Features 0-3: Network throughput metrics (extremely low for U2R)
            features[0] = random.uniform(0.0, 0.2) * intensity  # Packet rate
            features[1] = random.uniform(0.1, 0.4) * intensity  # Byte rate (slightly higher for payloads)
            features[2] = random.uniform(0.3, 0.6) * intensity  # Packet size (medium for exploit payloads)
            features[3] = random.uniform(0.0, 0.2) * intensity  # Flow volume
            
            # Features 4-6: Connection characteristics
            features[4] = random.uniform(0.7, 1.0) * intensity  # Connection duration (high)
            features[5] = random.uniform(0.0, 0.2) * intensity  # Connection frequency (very low)
            features[6] = random.uniform(0.1, 0.3) * intensity  # Connection repetition (low)
            
            # Features 7-10: Protocol characteristics
            features[7] = random.uniform(0.2, 0.5) * intensity if random.random() < 0.3 else 0  # TCP flags
            features[8] = random.uniform(0.0, 0.2) * intensity  # Protocol diversity (very low)
            features[9] = random.uniform(0.6, 1.0) * intensity  # Protocol anomaly (high)
            features[10] = random.uniform(0.0, 0.1) * intensity  # ICMP traffic (negligible)
            
            # Features 11-14: Target characteristics
            features[11] = random.uniform(0.0, 0.1) * intensity  # Target IP diversity (extremely low - single target)
            features[12] = random.uniform(0.0, 0.3) * intensity  # Target port diversity (very low)
            features[13] = random.uniform(0.0, 0.2) * intensity  # Target service diversity (very low)
            features[14] = random.uniform(0.0, 0.2) * intensity  # Server load indicator (very low)
            
            # Features 15-19: Time-based characteristics
            features[15] = random.uniform(0.0, 0.3) * intensity  # Traffic regularity (low)
            features[16] = random.uniform(0.3, 0.7) * intensity  # Burst intensity (medium)
            features[17] = random.uniform(0.7, 1.0) * intensity  # Time between connections (very high)
            features[18] = random.uniform(0.7, 1.0) * intensity  # Persistence indicator (high)
            features[19] = random.uniform(0.6, 1.0) * intensity if random.random() < 0.8 else 0  # Time pattern anomaly
            
            # Add randomness based on inverse of intensity
            randomness = (1.0 - intensity) * 0.3
            features = [max(0, min(1, f + random.uniform(-randomness, randomness))) for f in features]
            
            # Add specific exploitation markers at certain positions
            # These are subtle signatures of privilege escalation
            if random.random() < intensity * 0.7:
                exploit_pos = random.randint(0, 19)
                features[exploit_pos] = min(1.0, features[exploit_pos] + random.uniform(0.3, 0.5) * intensity)
            
            # Create packet data
            packet = {
                "type": "traffic",
                "attack_type": "u2r",
                "features": features,
                "intensity": intensity,
                "synthetic": True,
                "timestamp": time.time()
            }
            
            packets.append(packet)
        
        return packets 