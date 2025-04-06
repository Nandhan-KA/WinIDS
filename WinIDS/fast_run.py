#!/usr/bin/env python
"""
WinIDS Fast IDS

Core intrusion detection functionality using optimized neural network models.
"""

import os
import sys
import time
import json
import queue
import socket
import logging
import threading
import traceback
from datetime import datetime

try:
    import numpy as np
    import tensorflow as tf
    from tensorflow.keras.models import load_model
except ImportError:
    print("Error: Required libraries not found. Please install tensorflow and numpy.")
    sys.exit(1)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("WinIDS_fast.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger("WinIDS-Fast")

# Import RL components if available
try:
    from .rl_agent import AdaptiveIDS
    RL_AVAILABLE = True
except ImportError:
    RL_AVAILABLE = False
    logger.warning("Reinforcement learning module not available. Running in basic mode.")

class FastIDS:
    """
    Fast IDS class that provides core intrusion detection functionality
    using optimized neural network models.
    """
    
    def __init__(self, model_path="models/best_fast_model.h5", 
                 norm_params_path="models/normalization_params.json",
                 threshold=0.7, bridge_host="localhost", bridge_port=5000,
                 use_rl=True, rl_model_dir="./rl_models", rl_training_mode=True):
        """Initialize the Fast IDS.
        
        Args:
            model_path: Path to the neural network model file
            norm_params_path: Path to the normalization parameters file
            threshold: Detection threshold for alerts
            bridge_host: Host address of the bridge
            bridge_port: Port of the bridge
            use_rl: Whether to use reinforcement learning
            rl_model_dir: Directory for RL models
            rl_training_mode: Whether RL is in training mode
        """
        self.model_path = model_path
        self.norm_params_path = norm_params_path
        self.threshold = threshold
        self.bridge_host = bridge_host
        self.bridge_port = bridge_port
        self.disable_attacks = False
        
        # Initialize model to None (will be loaded on start)
        self.model = None
        self.norm_params = None
        
        # Connection components
        self.socket = None
        self.running = False
        self.receive_thread = None
        self.bridge_connected = False
        
        # Traffic processing
        self.latest_traffic = None
        self.traffic_buffer = []
        self.buffer_size = 10  # Number of packets to buffer before prediction
        
        # Statistics
        self.start_time = time.time()
        self.stats = {
            'total_packets': 0,
            'alerts': 0,
            'true_positives': 0,
            'false_positives': 0,
            'dos_alerts': 0,
            'probe_alerts': 0,
            'r2l_alerts': 0,
            'u2r_alerts': 0,
            'avg_confidence': 0.5,
            'threshold': threshold,
            'uptime': 0
        }
        
        # Alert queue for dashboard
        self.alert_queue = queue.Queue()
        
        # Reinforcement learning components
        self.use_rl = use_rl and RL_AVAILABLE
        self.adaptive_ids = None
        self.rl_model_dir = rl_model_dir
        self.rl_training_mode = rl_training_mode
        
        if self.use_rl:
            # Initialize the adaptive IDS with reinforcement learning
            try:
                self.adaptive_ids = AdaptiveIDS(
                    base_threshold=threshold,
                    model_dir=rl_model_dir,
                    training_mode=rl_training_mode
                )
                logger.info("Reinforcement learning initialized")
            except Exception as e:
                logger.error(f"Failed to initialize reinforcement learning: {str(e)}")
                self.use_rl = False
        
        # Initial logging
        logger.info(f"FastIDS initialized with threshold {threshold}")
        logger.info(f"Reinforcement learning: {'Enabled' if self.use_rl else 'Disabled'}")
        logger.info(f"Model path: {model_path}")
        logger.info(f"Bridge connection: {bridge_host}:{bridge_port}")
    
    def load_model_files(self):
        """Load the TensorFlow model and normalization parameters."""
        try:
            # Load the model
            if not os.path.exists(self.model_path):
                logger.error(f"Model file not found: {self.model_path}")
                return False
                
            self.model = load_model(self.model_path)
            logger.info(f"Model loaded from {self.model_path}")
            
            # Load normalization parameters
            if not os.path.exists(self.norm_params_path):
                logger.error(f"Normalization parameters file not found: {self.norm_params_path}")
                return False
                
            with open(self.norm_params_path, 'r') as f:
                self.norm_params = json.load(f)
            
            logger.info(f"Normalization parameters loaded from {self.norm_params_path}")
            
            # Load RL model state if available
            if self.use_rl and self.adaptive_ids:
                self.adaptive_ids.load_state()
                # Update threshold from RL if needed
                self.threshold = self.adaptive_ids.threshold
                self.stats['threshold'] = self.threshold
                logger.info(f"Using RL-adjusted threshold: {self.threshold}")
                
            return True
            
        except Exception as e:
            logger.error(f"Error loading model: {str(e)}")
            logger.error(traceback.format_exc())
            return False
    
    def connect_to_bridge(self):
        """Connect to the IDS Bridge to receive traffic data."""
        if self.bridge_connected:
            logger.info("Already connected to bridge")
            return True
            
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.settimeout(10)
            self.socket.connect((self.bridge_host, self.bridge_port))
            
            # Send initial handshake
            handshake = {
                "type": "connect",
                "client": "WinIDS-fast",
                "version": "0.1.1",
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }
            self.socket.send((json.dumps(handshake) + "\n").encode())
            
            # Set as connected
            self.bridge_connected = True
            logger.info(f"Connected to IDS Bridge at {self.bridge_host}:{self.bridge_port}")
            
            return True
            
        except Exception as e:
            logger.error(f"Error connecting to IDS Bridge: {str(e)}")
            if self.socket:
                self.socket.close()
                self.socket = None
            return False
    
    def receive_data_thread(self):
        """Thread function to receive data from the bridge."""
        buffer = ""
        
        while self.running and self.socket:
            try:
                # Receive data
                data = self.socket.recv(4096)
                if not data:
                    # Connection closed
                    logger.warning("Bridge connection closed")
                    self.bridge_connected = False
                    break
                
                # Decode and process data
                buffer += data.decode()
                
                # Process complete messages
                while "\n" in buffer:
                    line, buffer = buffer.split("\n", 1)
                    self._process_traffic_data(line)
                    
            except socket.timeout:
                # Just continue on timeout
                continue
            except Exception as e:
                logger.error(f"Error receiving data: {str(e)}")
                self.bridge_connected = False
                break
        
        # Clean up socket
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
            self.socket = None
        
        self.bridge_connected = False
        logger.info("Receive thread stopped")
    
    def _process_traffic_data(self, data_str):
        """Process received traffic data."""
        try:
            # Parse JSON data
            data = json.loads(data_str)
            
            if "type" not in data:
                return
            
            if data["type"] == "traffic":
                self.latest_traffic = data
                self.stats['total_packets'] += 1
                
                # Add to buffer
                if "features" in data:
                    self.traffic_buffer.append(data["features"])
                    
                    # If we have enough data, predict
                    if len(self.traffic_buffer) >= self.buffer_size:
                        self.predict_traffic()
                        
            elif data["type"] == "feedback":
                # Process feedback data (for reinforcement learning)
                self._process_feedback(data)
                        
        except Exception as e:
            logger.error(f"Error processing traffic data: {str(e)}")
            logger.error(traceback.format_exc())
    
    def _process_feedback(self, feedback_data):
        """Process feedback for reinforcement learning."""
        if not self.use_rl or not self.adaptive_ids:
            return
            
        try:
            # Extract feedback information
            alert_id = feedback_data.get("alert_id")
            is_attack = feedback_data.get("is_attack", False)
            confidence = feedback_data.get("confidence", 0.5)
            
            # Use feedback to adapt threshold
            new_threshold, threshold_change = self.adaptive_ids.adapt_threshold(confidence, is_attack)
            
            # Update our threshold
            if threshold_change != 0:
                self.threshold = new_threshold
                self.stats['threshold'] = new_threshold
                logger.info(f"RL adjusted threshold: {self.threshold:0.3f} (change: {threshold_change:+0.3f})")
                
        except Exception as e:
            logger.error(f"Error processing feedback: {str(e)}")
    
    def predict_traffic(self):
        """Predict if traffic is malicious."""
        if not self.model or not self.norm_params:
            logger.error("Model or normalization parameters not loaded")
            self.traffic_buffer = []
            return
            
        try:
            # Prepare batch of features
            features_batch = np.array(self.traffic_buffer)
            
            # Normalize features
            means = np.array(self.norm_params["mean"])
            stds = np.array(self.norm_params["std"])
            normalized_features = (features_batch - means) / stds
            
            # Perform prediction
            predictions = self.model.predict(normalized_features, verbose=0)
            
            # Process predictions
            for i, pred in enumerate(predictions):
                confidence = float(np.max(pred))
                attack_type_idx = np.argmax(pred)
                
                # Normalize output to 5 types (normal, dos, probe, r2l, u2r)
                attack_types = ["normal", "dos", "probe", "r2l", "u2r"]
                attack_type = attack_types[attack_type_idx] if attack_type_idx < len(attack_types) else "unknown"
                
                # Get current threshold (may be adapted by RL)
                current_threshold = self.threshold
                if self.use_rl and self.adaptive_ids:
                    current_threshold = self.adaptive_ids.threshold
                
                # Update average confidence for RL state
                self.stats['avg_confidence'] = 0.9 * self.stats['avg_confidence'] + 0.1 * confidence
                
                # Check if prediction exceeds threshold
                if confidence >= current_threshold and attack_type != "normal":
                    # We have an alert
                    self.stats['alerts'] += 1
                    
                    # Update attack-specific counters
                    counter_key = f"{attack_type}_alerts"
                    if counter_key in self.stats:
                        self.stats[counter_key] += 1
                    
                    # Create alert object
                    alert = {
                        "id": f"alert-{self.stats['total_packets']}-{self.stats['alerts']}",
                        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                        "confidence": confidence,
                        "attack_type": attack_type,
                        "severity": self._calculate_severity(confidence, attack_type),
                        "traffic_data": self.latest_traffic.get("traffic_data", {}) if self.latest_traffic else {},
                        "threshold": current_threshold
                    }
                    
                    # Update adaptive threshold if RL is enabled
                    if self.use_rl and self.adaptive_ids:
                        # Use RL to suggest threshold adjustment based on recent performance
                        metrics = {
                            **self.stats,
                            'confidence': confidence
                        }
                        self.adaptive_ids.update_metrics(metrics)
                    
                    # Add to alert queue for the dashboard
                    self.alert_queue.put(alert)
                    
                    logger.info(f"Alert detected: {attack_type} (confidence: {confidence:.3f})")
            
            # Clear buffer
            self.traffic_buffer = []
            
        except Exception as e:
            logger.error(f"Error predicting traffic: {str(e)}")
            logger.error(traceback.format_exc())
            self.traffic_buffer = []
    
    def _calculate_severity(self, confidence, attack_type):
        """Calculate alert severity based on confidence and attack type."""
        # Base severity on confidence
        if confidence > 0.9:
            base_severity = "critical"
        elif confidence > 0.8:
            base_severity = "high"
        elif confidence > 0.7:
            base_severity = "medium"
        else:
            base_severity = "low"
            
        # Adjust for attack type
        if attack_type == "u2r":  # User to Root - most severe
            severity_modifier = 1
        elif attack_type == "r2l":  # Remote to Local
            severity_modifier = 0
        elif attack_type == "dos":  # Denial of Service
            severity_modifier = -0.5
        elif attack_type == "probe":  # Probing - least severe
            severity_modifier = -1
        else:
            severity_modifier = 0
            
        # Apply modifier
        severity_levels = ["low", "medium", "high", "critical"]
        idx = severity_levels.index(base_severity)
        adjusted_idx = max(0, min(len(severity_levels)-1, idx + severity_modifier))
        
        return severity_levels[int(adjusted_idx)]
    
    def start(self):
        """Start the IDS."""
        if self.running:
            logger.info("IDS already running")
            return True
            
        logger.info("Starting WinIDS Fast IDS...")
        
        # Load model
        if not self.load_model_files():
            logger.error("Failed to load model files")
            return False
            
        # Connect to bridge
        if not self.connect_to_bridge():
            logger.error("Failed to connect to bridge")
            return False
            
        # Start receive thread
        self.running = True
        self.receive_thread = threading.Thread(target=self.receive_data_thread)
        self.receive_thread.daemon = True
        self.receive_thread.start()
        
        # Start RL adjustment thread if enabled
        if self.use_rl and self.adaptive_ids:
            self.adaptive_ids.start_adjustment_thread(interval=60)
            logger.info("Started RL adjustment thread")
        
        logger.info("WinIDS Fast IDS started successfully")
        return True
    
    def stop(self):
        """Stop the IDS."""
        if not self.running:
            logger.info("IDS not running")
            return
            
        logger.info("Stopping WinIDS Fast IDS...")
        
        # Set flag to stop threads
        self.running = False
        
        # Stop RL components if enabled
        if self.use_rl and self.adaptive_ids:
            self.adaptive_ids.stop()
            self.adaptive_ids.save_state()
            logger.info("Stopped RL components and saved state")
        
        # Wait for receive thread to stop
        if self.receive_thread and self.receive_thread.is_alive():
            self.receive_thread.join(timeout=5.0)
            
        # Close connection
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
            self.socket = None
            
        self.bridge_connected = False
        logger.info("WinIDS Fast IDS stopped")
    
    def get_stats(self):
        """Get current statistics."""
        # Update uptime
        self.stats['uptime'] = int(time.time() - self.start_time)
        
        # Return copy of stats
        return dict(self.stats)


def main():
    """Main function for CLI usage."""
    import argparse
    
    parser = argparse.ArgumentParser(description="WinIDS Fast IDS")
    parser.add_argument("--model", default="models/best_fast_model.h5", help="Path to model file")
    parser.add_argument("--norm-params", default="models/normalization_params.json", help="Path to normalization parameters")
    parser.add_argument("--threshold", type=float, default=0.7, help="Detection threshold")
    parser.add_argument("--bridge-host", default="localhost", help="Bridge host")
    parser.add_argument("--bridge-port", type=int, default=5000, help="Bridge port")
    parser.add_argument("--disable-rl", action="store_true", help="Disable reinforcement learning")
    parser.add_argument("--rl-model-dir", default="./rl_models", help="Directory for RL models")
    parser.add_argument("--disable-rl-training", action="store_true", help="Disable RL training mode")
    
    args = parser.parse_args()
    
    # Create FastIDS instance
    ids = FastIDS(
        model_path=args.model,
        norm_params_path=args.norm_params,
        threshold=args.threshold,
        bridge_host=args.bridge_host,
        bridge_port=args.bridge_port,
        use_rl=not args.disable_rl,
        rl_model_dir=args.rl_model_dir,
        rl_training_mode=not args.disable_rl_training
    )
    
    # Start the IDS
    if not ids.start():
        logger.error("Failed to start IDS")
        sys.exit(1)
        
    try:
        while True:
            time.sleep(1)
            stats = ids.get_stats()
            # Print statistics periodically
            print(f"\rPackets: {stats['total_packets']}, "
                  f"Alerts: {stats['alerts']}, "
                  f"Threshold: {stats['threshold']:.3f}", end="")
    except KeyboardInterrupt:
        print("\nStopping IDS...")
        ids.stop()
        

if __name__ == "__main__":
    main() 