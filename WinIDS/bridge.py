#!/usr/bin/env python
"""
WinIDS Bridge - Traffic Generator

This module acts as a bridge between traffic sources and the IDS system.
It generates and forwards network traffic data to monitoring components.
"""

import os
import sys
import time
import json
import socket
import logging
import argparse
import threading
import random
from datetime import datetime

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("WinIDS_bridge.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("WinIDS-Bridge")

class IDSBridge:
    """
    Bridge between traffic sources and IDS monitoring systems.
    
    Generates and forwards traffic data (normal and attack) to
    connected monitoring systems.
    """
    
    def __init__(self, config):
        """
        Initialize the IDS Bridge.
        
        Args:
            config: Configuration dictionary with parameters
        """
        self.config = config
        self.model_path = config.get('model_path')
        self.norm_params_path = config.get('norm_params_path')
        self.real_data_path = config.get('real_data_path')
        self.traffic_rate = config.get('traffic_rate', 1.0)
        self.attack_probability = config.get('attack_probability', 0.5)
        self.duration = config.get('duration', 0)
        self.monitor_host = config.get('monitor_host', 'localhost')
        self.monitor_port = config.get('monitor_port', 5000)
        self.use_file = config.get('use_file', False)
        self.traffic_file = config.get('traffic_file', 'traffic_data.json')
        
        # Load real data if provided
        self.real_data = []
        if self.real_data_path and os.path.exists(self.real_data_path):
            try:
                with open(self.real_data_path, 'r') as f:
                    self.real_data = json.load(f)
                logger.info(f"Loaded {len(self.real_data)} real traffic samples")
            except Exception as e:
                logger.error(f"Error loading real data: {e}")
        
        # Socket connection to monitor
        self.socket = None
        
        # Running state
        self.running = False
        self.stop_event = threading.Event()
            
    def _connect_to_monitor(self):
        """Connect to the IDS Monitor."""
        try:
            # Create a socket connection to the monitor
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.monitor_host, self.monitor_port))
            logger.info(f"Connected to IDS Monitor at {self.monitor_host}:{self.monitor_port}")
            return True
        except Exception as e:
            logger.error(f"Failed to connect to IDS Monitor: {e}")
            self.socket = None
            return False
            
    def _send_traffic_to_monitor(self, traffic_data):
        """
        Send traffic data to the IDS Monitor.
        
        Args:
            traffic_data: Traffic data to send
            
        Returns:
            bool: True if sent successfully, False otherwise
        """
        if self.use_file:
            # Write to file instead of socket
            try:
                with open(self.traffic_file, 'w') as f:
                    json.dump(traffic_data, f)
                return True
            except Exception as e:
                logger.error(f"Error writing to traffic file: {e}")
                return False
        else:
            # Send via socket
            if not self.socket and not self._connect_to_monitor():
                return False
                
            try:
                # Send the JSON data with a newline terminator
                message = json.dumps(traffic_data).encode('utf-8') + b'\n'
                self.socket.sendall(message)
                return True
            except Exception as e:
                logger.error(f"Error sending to monitor: {e}")
                self.socket = None  # Reset the socket
                return False
    
    def _generate_traffic(self):
        """
        Generate traffic data (normal or attack).
        
        Returns:
            dict: Generated traffic data
        """
        is_attack = random.random() < self.attack_probability
        
        if self.real_data:
            # Use real data if available
            if is_attack:
                # Find attack samples
                attack_samples = [s for s in self.real_data if s.get('is_attack', False)]
                if attack_samples:
                    return random.choice(attack_samples)
                    
            # Find normal samples or use any if no specific type is found
            normal_samples = [s for s in self.real_data if not s.get('is_attack', False)]
            if normal_samples:
                return random.choice(normal_samples)
            elif self.real_data:
                return random.choice(self.real_data)
        
        # Generate synthetic data if no real data
        attack_type = 'normal'
        if is_attack:
            attack_type = random.choice(['dos', 'probe', 'r2l', 'u2r'])
            
        # Generate random features
        features = [random.random() for _ in range(41)]
        
        # Create traffic data
        return {
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f'),
            'features': features,
            'attack_type': attack_type,
            'is_attack': is_attack
        }
            
    def run(self):
        """Run the bridge, generating and sending traffic data."""
        logger.info("Starting IDS Bridge")
        logger.info(f"Traffic rate set to: {self.traffic_rate} events/s")
        logger.info(f"Attack probability set to: {self.attack_probability}")
        
        if self.config.get('disable_attacks', False):
            logger.warning("=== AUTO-ATTACKS COMPLETELY DISABLED ===")
            logger.warning("No traffic will be generated - IDS Bridge is in PASSIVE mode")
            logger.warning("Only manual commands via attack panel will be processed")
            
            # Force all traffic and attack settings to zero regardless of what was passed
            self.traffic_rate = 0.0
            self.attack_probability = 0.0
            
            # Start a server socket to listen for attack panel commands only
            server_thread = threading.Thread(target=self._start_server, daemon=True)
            server_thread.start()
            
            # Just wait indefinitely without generating any traffic
            self.running = True
            while self.running and not self.stop_event.is_set():
                time.sleep(1)
                
            logger.info("IDS Bridge stopped")
            return
        
        # Regular traffic generation (only if attacks are not disabled)
        # Calculate sleep time between events
        sleep_time = 1.0 / max(0.1, self.traffic_rate)  # At least 0.1 events/s
        
        # Start a server socket to listen for attack panel commands
        server_thread = threading.Thread(target=self._start_server, daemon=True)
        server_thread.start()
        
        # Start traffic generation
        self.running = True
        self.traffic_generated = 0
        start_time = time.time()
        
        while self.running and not self.stop_event.is_set():
            # Check if duration exceeded
            if self.duration > 0 and (time.time() - start_time) > self.duration:
                logger.info(f"Duration of {self.duration}s exceeded")
                break
                
            # Generate and send traffic
            traffic_data = self._generate_traffic()
            success = self._send_traffic_to_monitor(traffic_data)
            
            if success:
                self.traffic_generated += 1
                if self.traffic_generated % 100 == 0:
                    logger.info(f"Generated {self.traffic_generated} traffic events")
            
            # Sleep until next event
            time.sleep(sleep_time)
            
        logger.info("IDS Bridge stopped")
        logger.info(f"Generated {self.traffic_generated} traffic events in total")
    
    def _start_server(self):
        """Start a server socket to listen for attack panel commands."""
        try:
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind(('0.0.0.0', self.monitor_port + 1))  # Use monitor_port + 1
            server_socket.listen(5)
            logger.info(f"Listening for attack panel commands on port {self.monitor_port + 1}")
            
            while self.running and not self.stop_event.is_set():
                try:
                    client_socket, _ = server_socket.accept()
                    client_socket.settimeout(5)
                    
                    # Handle command in a separate thread
                    threading.Thread(
                        target=self._handle_command, 
                        args=(client_socket,),
                        daemon=True
                    ).start()
                except socket.timeout:
                    continue
                except Exception as e:
                    logger.error(f"Error accepting connection: {e}")
        except Exception as e:
            logger.error(f"Error starting server: {e}")
        finally:
            try:
                server_socket.close()
            except:
                pass
    
    def _handle_command(self, client_socket):
        """Handle a command from the attack panel."""
        try:
            # Receive data
            data = b''
            while not data.endswith(b'\n'):
                chunk = client_socket.recv(1024)
                if not chunk:
                    break
                data += chunk
            
            # Parse command
            if data:
                command = json.loads(data.decode('utf-8'))
                
                # Check if attacks are disabled - block ALL attack commands when disable_attacks is set
                # This includes both auto and manual attacks
                if self.config.get('disable_attacks', False) and command.get('type') == 'attack':
                    logger.warning(f"REJECTED ATTACK: Received attack command but attacks are completely disabled")
                    logger.warning(f"Attack details: {command.get('attack_type', 'unknown')} with intensity {command.get('intensity', 0)}")
                    client_socket.sendall(json.dumps({
                        'status': 'error',
                        'message': 'Attacks are disabled. The --disable-attacks flag was set when starting the bridge.'
                    }).encode('utf-8') + b'\n')
                    return
                
                # Process command
                if command.get('type') == 'attack':
                    # Generate and send attack
                    attack_type = command.get('attack_type', 'dos')
                    intensity = command.get('intensity', 0.7)
                    count = command.get('count', 1)
                    
                    logger.info(f"Received request to generate {count} {attack_type} attack(s) with intensity {intensity}")
                    
                    # Generate and send attacks
                    for _ in range(count):
                        # Create attack data
                        attack_data = {
                            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f'),
                            'features': [random.random() * intensity for _ in range(41)],
                            'attack_type': attack_type,
                            'is_attack': True
                        }
                        
                        # Add custom features if provided
                        if 'custom_features' in command:
                            for i, value in command['custom_features'].items():
                                try:
                                    idx = int(i)
                                    if 0 <= idx < len(attack_data['features']):
                                        attack_data['features'][idx] = float(value)
                                except:
                                    pass
                                    
                        # Add source/destination if provided
                        for field in ['src_ip', 'src_port', 'dst_ip', 'dst_port']:
                            if field in command:
                                attack_data[field] = command[field]
                        
                        # Send to monitor
                        self._send_traffic_to_monitor(attack_data)
                        
                        # Sleep briefly between attacks
                        time.sleep(0.1)
                    
                    # Send success response
                    client_socket.sendall(json.dumps({
                        'status': 'success',
                        'message': f'Generated {count} {attack_type} attack(s)'
                    }).encode('utf-8') + b'\n')
                
                elif command.get('type') == 'heartbeat':
                    # Just send back an OK
                    client_socket.sendall(json.dumps({
                        'status': 'ok'
                    }).encode('utf-8') + b'\n')
                    
                else:
                    # Unknown command
                    logger.warning(f"Unknown command: {command.get('type')}")
                    client_socket.sendall(json.dumps({
                        'status': 'error',
                        'message': 'Unknown command'
                    }).encode('utf-8') + b'\n')
                
        except Exception as e:
            logger.error(f"Error handling command: {e}")
        finally:
            client_socket.close()

    def stop(self):
        """Stop the bridge."""
        self.stop_event.set()
        self.running = False

    def send_feedback(self, feedback_data):
        """Send feedback data for reinforcement learning.
        
        Args:
            feedback_data: Dictionary containing feedback information:
                - alert_id: ID of the alert being evaluated
                - is_attack: Boolean indicating if it was a real attack
                - confidence: Confidence value from the original alert
                
        Returns:
            bool: True if sent successfully, False otherwise
        """
        # Ensure feedback data has the correct type
        if isinstance(feedback_data, dict) and 'type' not in feedback_data:
            feedback_data['type'] = 'feedback'
            
        # Add timestamp if not present
        if 'timestamp' not in feedback_data:
            feedback_data['timestamp'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')
            
        # Send feedback to the monitor
        logger.info(f"Sending feedback: {feedback_data.get('is_attack', False)}, "
                  f"Alert ID: {feedback_data.get('alert_id', 'unknown')}")
        
        return self._send_traffic_to_monitor(feedback_data)
    
    def start(self):
        """Start the bridge in a separate thread."""
        if self.running:
            logger.info("Bridge already running")
            return True
            
        # Start a thread to run the bridge
        self.thread = threading.Thread(target=self.run)
        self.thread.daemon = True
        self.thread.start()
        
        # Wait a short time to ensure the bridge starts
        time.sleep(0.5)
        
        return self.running

def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='WinIDS Bridge - Traffic Generator')
    
    parser.add_argument('--model', type=str, default=None,
                      help='Path to IDS model')
    parser.add_argument('--norm-params', type=str, default=None,
                      help='Path to normalization parameters')
    parser.add_argument('--real-data', type=str, default=None,
                      help='Path to real network traffic data')
    parser.add_argument('--traffic-rate', type=float, default=1.0,
                      help='Traffic generation rate (events per second)')
    parser.add_argument('--attack-probability', type=float, default=0.5,
                      help='Probability of generating attack traffic')
    parser.add_argument('--duration', type=int, default=0,
                      help='Duration of traffic generation in seconds (0 for indefinite)')
    parser.add_argument('--monitor-host', type=str, default='localhost',
                      help='IDS Monitor host')
    parser.add_argument('--monitor-port', type=int, default=5000,
                      help='IDS Monitor port')
    parser.add_argument('--use-file', action='store_true',
                      help='Use file-based communication instead of socket')
    parser.add_argument('--traffic-file', type=str, default='traffic_data.json',
                      help='Traffic data file for file-based communication')
    parser.add_argument('--no-auto-attacks', action='store_true',
                      help='Disable automatic attack generation')
    parser.add_argument('--disable-attacks', action='store_true',
                      help='Completely disable all attack functionality')
    
    return parser.parse_args()

def main():
    """Main entry point."""
    # Parse command line arguments
    args = parse_args()
    
    # If no-auto-attacks flag is set, set attack probability to 0
    if args.no_auto_attacks:
        args.attack_probability = 0.0
        
    # Override attack probability if disable-attacks is set
    if args.disable_attacks:
        args.attack_probability = 0.0
        args.traffic_rate = 0.0  # Also explicitly set traffic rate to 0
        logger.warning("==================================================")
        logger.warning("ATTACK FUNCTIONALITY COMPLETELY DISABLED")
        logger.warning("The bridge will not generate ANY traffic (normal or attacks)")
        logger.warning("Only manual commands via the attack panel will be allowed")
        logger.warning("==================================================")
    
    # Create config dictionary from arguments
    config = {
        'model_path': args.model,
        'norm_params_path': args.norm_params,
        'real_data_path': args.real_data,
        'traffic_rate': args.traffic_rate,
        'attack_probability': args.attack_probability,
        'duration': args.duration,
        'monitor_host': args.monitor_host,
        'monitor_port': args.monitor_port,
        'use_file': args.use_file,
        'traffic_file': args.traffic_file,
        'disable_attacks': args.disable_attacks
    }
    
    # Create and run bridge
    bridge = IDSBridge(config)
    bridge.run()

if __name__ == "__main__":
    sys.exit(main()) 