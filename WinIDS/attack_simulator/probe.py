"""
Probe attack simulator (network scanning and reconnaissance)
"""

import random
import time
import logging
from .base import BaseAttackSimulator

logger = logging.getLogger("WinIDS-ProbeAttackSimulator")

class ProbeAttackSimulator(BaseAttackSimulator):
    """Simulator for Probe attacks (scanning and reconnaissance)"""
    
    def __init__(self):
        """Initialize the Probe attack simulator"""
        super().__init__(attack_type="probe")
        
        # Probe attack characteristics
        self.characteristics = {
            "port_scanning": True,
            "broad_target_range": True,
            "low_traffic_volume": True,
            "diverse_probe_types": True
        }
        
    def generate(self, intensity=0.5, duration=10):
        """Generate Probe attack traffic
        
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
        
        # Probe attacks typically have fewer packets than DOS
        packet_count = int(packet_count * 0.1)
        
        logger.info(f"Generating Probe attack with {packet_count} packets (intensity: {intensity}, duration: {duration}s)")
        
        # Generate attack packets
        packets = []
        
        # Probe attack feature patterns
        for i in range(packet_count):
            # Base features (20 features)
            features = [0.0] * 20
            
            # Set typical Probe attack patterns in features
            # Features 0-3: Network throughput metrics (low for probe)
            features[0] = random.uniform(0.1, 0.4) * intensity  # Packet rate
            features[1] = random.uniform(0.1, 0.3) * intensity  # Byte rate
            features[2] = random.uniform(0.1, 0.4) * intensity  # Packet size
            features[3] = random.uniform(0.1, 0.3) * intensity  # Flow volume
            
            # Features 4-6: Connection characteristics
            features[4] = random.uniform(0.1, 0.4) * intensity  # Connection duration
            features[5] = random.uniform(0.5, 0.8) * intensity  # Connection frequency
            features[6] = random.uniform(0.1, 0.4) * intensity  # Connection repetition
            
            # Features 7-10: Protocol characteristics
            features[7] = random.uniform(0.5, 0.9) * intensity if random.random() < 0.6 else 0  # TCP flags (SYN scans)
            features[8] = random.uniform(0.6, 0.9) * intensity  # Protocol diversity (high)
            features[9] = random.uniform(0.4, 0.7) * intensity  # Protocol anomaly
            features[10] = random.uniform(0.3, 0.6) * intensity if random.random() < 0.5 else 0  # ICMP traffic
            
            # Features 11-14: Target characteristics
            features[11] = random.uniform(0.7, 1.0) * intensity  # Target IP diversity (high - wide scan)
            features[12] = random.uniform(0.7, 1.0) * intensity  # Target port diversity (high - port scan)
            features[13] = random.uniform(0.6, 0.9) * intensity  # Target service diversity (high)
            features[14] = random.uniform(0.1, 0.4) * intensity  # Server load indicator (low)
            
            # Features 15-19: Time-based characteristics
            features[15] = random.uniform(0.5, 0.8) * intensity  # Traffic regularity (medium)
            features[16] = random.uniform(0.2, 0.5) * intensity  # Burst intensity (low)
            features[17] = random.uniform(0.4, 0.7) * intensity  # Time between connections (medium)
            features[18] = random.uniform(0.3, 0.6) * intensity  # Persistence indicator (medium)
            features[19] = random.uniform(0.5, 0.8) * intensity if random.random() < 0.7 else 0  # Time pattern anomaly
            
            # Add randomness based on inverse of intensity
            randomness = (1.0 - intensity) * 0.3
            features = [max(0, min(1, f + random.uniform(-randomness, randomness))) for f in features]
            
            # Create packet data
            packet = {
                "type": "traffic",
                "attack_type": "probe",
                "features": features,
                "intensity": intensity,
                "synthetic": True,
                "timestamp": time.time()
            }
            
            packets.append(packet)
        
        return packets 