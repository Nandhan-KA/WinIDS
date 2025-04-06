#!/usr/bin/env python
"""
WinIDS Monitor - Connection Manager for WinIDS System

This script acts as a connection manager between the WinIDS Bridge (traffic generator)
and the WinIDS System. It accepts connections from WinIDS clients and forwards traffic data.
"""

import os
import sys
import time
import json
import socket
import logging
import argparse
import threading
from datetime import datetime
import random

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("WinIDS_monitor.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("WinIDS-Monitor")

class IDSMonitor:
    """
    WinIDS Monitor that manages connections between bridge and IDS clients.
    
    The monitor accepts connections from IDS clients and forwards
    traffic data from the bridge to connected clients.
    """
    
    def __init__(self, config):
        """
        Initialize the WinIDS Monitor.
        
        Args:
            config: Configuration dictionary with parameters
        """
        self.config = config
        self.host = config.get('host', 'localhost')
        self.port = config.get('port', 5000)
        self.check_interval = config.get('check_interval', 0.1)
        self.traffic_file = config.get('traffic_file', 'traffic_data.json')
        
        # Socket and clients
        self.server_socket = None
        self.socket_clients = set()
        
        # Running state
        self.running = False
        self.stop_event = threading.Event()
        
        # Statistics
        self.injection_count = 0
        self.connection_count = 0
        self.last_data = None
        
    def start(self):
        """Start the monitor in a separate thread."""
        if self.running:
            logger.info("Monitor already running")
            return True
            
        # Set up server socket
        if not self._setup_server_socket():
            logger.error("Failed to set up server socket, cannot continue")
            return False
            
        # Start a thread to run the monitor
        self.thread = threading.Thread(target=self.run)
        self.thread.daemon = True
        self.thread.start()
        
        # Wait a short time to ensure the monitor starts
        time.sleep(0.5)
        
        # Set as running
        self.running = True
        
        return True
        
    def _setup_server_socket(self):
        """Set up the server socket to accept connections from IDS clients."""
        try:
            # Create a TCP/IP socket
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            # Bind the socket to the port
            server_address = (self.host, self.port)
            logger.info(f"Starting WinIDS Monitor on {server_address[0]}:{server_address[1]}")
            self.server_socket.bind(server_address)
            
            # Listen for incoming connections
            self.server_socket.listen(5)
            self.server_socket.settimeout(0.5)  # Non-blocking with timeout
            
            return True
        except Exception as e:
            logger.error(f"Failed to set up server socket: {e}")
            return False
            
    def _accept_connections(self):
        """Accept connections from IDS clients."""
        if not self.server_socket:
            return
            
        try:
            # Accept connection
            client_socket, client_address = self.server_socket.accept()
            client_socket.settimeout(1.0)  # Set a timeout
            
            # Add to clients set
            self.socket_clients.add(client_socket)
            self.connection_count += 1
            
            logger.info(f"Accepted connection from {client_address[0]}:{client_address[1]}")
            logger.info(f"Total connections: {len(self.socket_clients)}")
        except socket.timeout:
            # Timeout - no connection received
            pass
        except Exception as e:
            logger.error(f"Error accepting connection: {e}")
            
    def _inject_via_socket(self, data):
        """Inject data via socket to connected IDS clients."""
        if not self.socket_clients:
            return False
        
        # Make a copy of client list to avoid modification during iteration
        clients = list(self.socket_clients)
        sent_count = 0
        
        for client in clients:
            try:
                # Send the data with a newline terminator
                message = json.dumps(data).encode('utf-8') + b'\n'
                client.sendall(message)
                sent_count += 1
                logger.info(f"Sent {data['attack_type']} traffic data to client ({len(message)} bytes)")
            except Exception as e:
                logger.warning(f"Error sending to client: {e}")
                try:
                    client.close()
                except:
                    pass
                self.socket_clients.remove(client)
                
        return sent_count > 0
    
    def _inject_via_command(self, data):
        """Inject data via command line interface."""
        try:
            print(f"INJECT: {json.dumps(data)}")
            return True
        except Exception as e:
            logger.error(f"Error injecting via command: {e}")
            return False
            
    def _inject_traffic_to_ids(self, traffic_data):
        """Inject traffic data to the IDS via the chosen method."""
        # Increment injection count
        self.injection_count += 1
        
        # Inject via socket
        result = self._inject_via_socket(traffic_data)
        
        return result
        
    def _get_latest_traffic(self):
        """Get the latest traffic data from the file."""
        if not os.path.exists(self.traffic_file):
            return None
            
        try:
            with open(self.traffic_file, 'r') as f:
                data = json.load(f)
                
            # Check if this is new data
            if self.last_data and data['timestamp'] == self.last_data['timestamp']:
                return None
                
            # Update last data
            self.last_data = data
            logger.info(f"Found new {data['attack_type']} traffic data in file")
            return data
        except Exception as e:
            logger.error(f"Error reading traffic file: {e}")
            return None
            
    def run(self):
        """Run the monitor, reading and injecting traffic data."""
        logger.info("Starting WinIDS Monitor")
        logger.info(f"Checking for traffic data every {self.check_interval} seconds")
        
        # Check if attacks are disabled
        disable_attacks = self.config.get('disable_attacks', False)
        if disable_attacks:
            logger.warning("=== ATTACK GENERATION DISABLED IN WinIDS MONITOR ===")
            logger.warning("Only normal traffic will be generated")
        
        # Set up server socket
        if not self._setup_server_socket():
            logger.error("Failed to set up server socket, cannot continue")
            return
        
        try:
            while not self.stop_event.is_set():
                # Accept new connections
                self._accept_connections()
                
                # Get latest traffic data from bridge
                if disable_attacks:
                    # Only generate normal traffic when attacks are disabled
                    traffic_data = {
                        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f'),
                        'features': [random.random() for _ in range(41)],
                        'attack_type': 'normal',
                        'is_attack': False
                    }
                else:
                    # Generate random traffic including attacks
                    traffic_data = {
                        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f'),
                        'features': [random.random() for _ in range(41)],
                        'attack_type': random.choice(['normal', 'dos', 'probe', 'r2l', 'u2r']),
                        'is_attack': random.random() < 0.8
                    }
                
                # Inject traffic data if we have clients
                if self.socket_clients:
                    injected = self._inject_traffic_to_ids(traffic_data)
                    if injected:
                        logger.info(f"Successfully injected {traffic_data['attack_type']} traffic to {len(self.socket_clients)} clients")
                        if self.injection_count % 10 == 0:
                            logger.info(f"Injected {self.injection_count} traffic events into IDS")
                    else:
                        logger.warning(f"Failed to inject {traffic_data['attack_type']} traffic - no active clients")
                
                # Sleep for the check interval
                time.sleep(self.check_interval)
                
        except KeyboardInterrupt:
            logger.info("Keyboard interrupt received")
        finally:
            # Clean up
            if self.server_socket:
                try:
                    self.server_socket.close()
                except:
                    pass
                    
            for client in self.socket_clients:
                try:
                    client.close()
                except:
                    pass
                    
            logger.info("WinIDS Monitor stopped")
            logger.info(f"Connections: {self.connection_count}")
            logger.info(f"Injections: {self.injection_count}")
            
    def stop(self):
        """Stop the monitor."""
        if not self.running:
            logger.info("Monitor not running")
            return
            
        logger.info("Stopping WinIDS Monitor...")
        
        # Signal threads to stop
        self.stop_event.set()
        self.running = False
        
        # Close all client connections
        for client in list(self.socket_clients):
            try:
                client.close()
            except:
                pass
        self.socket_clients.clear()
            
        # Close server socket
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
            self.server_socket = None
            
        # Wait for thread to end
        if hasattr(self, 'thread') and self.thread and self.thread.is_alive():
            self.thread.join(timeout=5.0)
            
        logger.info("WinIDS Monitor stopped")
            
def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="WinIDS Monitor - Connection Manager")
    
    parser.add_argument("--host", type=str, default="localhost",
                      help="Host to listen on")
    parser.add_argument("--port", type=int, default=5000,
                      help="Port to listen on")
    parser.add_argument("--check-interval", type=float, default=0.1,
                      help="Interval in seconds to check for new traffic data")
    parser.add_argument("--traffic-file", type=str, default="traffic_data.json",
                      help="Traffic data file to read from")
    parser.add_argument("--disable-attacks", action="store_true",
                      help="Completely disable all attack traffic generation")
    
    return parser.parse_args()

def main():
    """Main entry point."""
    # Parse command line arguments
    args = parse_args()
    
    # Create config dictionary from arguments
    config = {
        'host': args.host,
        'port': args.port,
        'check_interval': args.check_interval,
        'traffic_file': args.traffic_file,
        'disable_attacks': args.disable_attacks
    }
    
    # Create and run monitor
    monitor = IDSMonitor(config)
    monitor.run()

if __name__ == "__main__":
    sys.exit(main()) 