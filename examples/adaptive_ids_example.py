#!/usr/bin/env python
"""
WinIDS Adaptive IDS Example

This example demonstrates how to use the reinforcement learning capabilities
of WinIDS to create an adaptive intrusion detection system.
"""

import time
import json
import os
import argparse
import random
from datetime import datetime

try:
    from WinIDS import FastIDS, IDSBridge, IDSMonitor, RL_AVAILABLE
except ImportError:
    print("WinIDS package not installed. Please install it first.")
    exit(1)

if not RL_AVAILABLE:
    print("Reinforcement learning components are not available.")
    print("This example requires the reinforcement learning components.")
    exit(1)


def simulate_feedback(ids, bridge, duration=300, feedback_interval=10):
    """Simulate user feedback for the RL agent.
    
    Args:
        ids: FastIDS instance
        bridge: IDSBridge instance
        duration: Duration in seconds to run the simulation
        feedback_interval: Seconds between feedback events
    """
    print(f"\nStarting adaptive IDS simulation for {duration} seconds")
    print("Press Ctrl+C to stop\n")
    
    # Initial threshold
    initial_threshold = ids.threshold
    print(f"Initial detection threshold: {initial_threshold:.3f}")
    
    start_time = time.time()
    last_feedback_time = start_time
    
    try:
        while time.time() - start_time < duration:
            # Get current stats
            stats = ids.get_stats()
            current_time = time.time()
            
            # Provide feedback periodically
            if current_time - last_feedback_time >= feedback_interval:
                # Generate simulated feedback
                # In a real scenario, this would come from user or automated validation
                
                # Random decision whether this was a real attack or false positive
                is_attack = random.random() > 0.3  # 70% chance it's a real attack
                
                feedback = {
                    "type": "feedback",
                    "alert_id": f"alert-{int(time.time())}-{random.randint(1000, 9999)}",
                    "is_attack": is_attack,
                    "confidence": 0.6 + random.random() * 0.3,  # 0.6-0.9 range
                    "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                }
                
                # Send feedback to the bridge
                if bridge.socket:
                    try:
                        # In a real scenario, bridge would route this feedback to the IDS
                        # Here we directly process it in the IDS
                        ids._process_traffic_data(json.dumps(feedback))
                        
                        print(f"Feedback sent: {'Real attack' if is_attack else 'False positive'}, "
                              f"Confidence: {feedback['confidence']:.3f}")
                        
                    except Exception as e:
                        print(f"Error sending feedback: {str(e)}")
                
                last_feedback_time = current_time
            
            # Display stats
            elapsed = current_time - start_time
            print(f"\r[{elapsed:.1f}s] Packets: {stats['total_packets']}, "
                  f"Alerts: {stats['alerts']}, "
                  f"Threshold: {stats['threshold']:.3f} "
                  f"(Δ: {stats['threshold'] - initial_threshold:+.3f})", end="")
            
            # Sleep a bit
            time.sleep(1)
            
    except KeyboardInterrupt:
        print("\n\nSimulation interrupted by user")
    
    # Final stats
    final_stats = ids.get_stats()
    print("\n\nAdaptive IDS Simulation Results:")
    print(f"Duration: {time.time() - start_time:.1f} seconds")
    print(f"Total packets: {final_stats['total_packets']}")
    print(f"Total alerts: {final_stats['alerts']}")
    print(f"Initial threshold: {initial_threshold:.3f}")
    print(f"Final threshold: {final_stats['threshold']:.3f}")
    print(f"Threshold change: {final_stats['threshold'] - initial_threshold:+.3f}")


def main():
    """Main function to run the example."""
    parser = argparse.ArgumentParser(description="WinIDS Adaptive IDS Example")
    parser.add_argument("--model", default="models/best_fast_model.h5", help="Path to model file")
    parser.add_argument("--norm-params", default="models/normalization_params.json", help="Path to normalization parameters")
    parser.add_argument("--duration", type=int, default=300, help="Duration of simulation in seconds")
    parser.add_argument("--feedback-interval", type=int, default=10, help="Seconds between feedback events")
    parser.add_argument("--rl-model-dir", default="./rl_models", help="Directory for RL models")
    parser.add_argument("--initial-threshold", type=float, default=0.7, help="Initial detection threshold")
    
    args = parser.parse_args()
    
    # Create directory for RL models if it doesn't exist
    if not os.path.exists(args.rl_model_dir):
        os.makedirs(args.rl_model_dir)
    
    # Create components
    print("Starting WinIDS components...")
    
    # Create and start the monitor
    monitor_config = {
        'host': 'localhost',
        'port': 5000,
        'check_interval': 1.0
    }
    monitor = IDSMonitor(monitor_config)
    if not monitor.start():
        print("Failed to start monitor")
        return
    
    # Create and start the bridge
    bridge_config = {
        'monitor_host': 'localhost',
        'monitor_port': 5000,
        'traffic_rate': 1.0,
        'attack_probability': 0.5,
        'duration': 0
    }
    bridge = IDSBridge(bridge_config)
    if not bridge.start():
        print("Failed to start bridge")
        monitor.stop()
        return
    
    # Create the IDS with reinforcement learning
    ids = FastIDS(
        model_path=args.model,
        norm_params_path=args.norm_params,
        threshold=args.initial_threshold,
        bridge_host="localhost",
        bridge_port=5000,
        use_rl=True,
        rl_model_dir=args.rl_model_dir,
        rl_training_mode=True
    )
    
    # Start the IDS
    if not ids.start():
        print("Failed to start IDS")
        bridge.stop()
        monitor.stop()
        return
    
    print("All components started successfully")
    
    # Run simulation
    try:
        simulate_feedback(
            ids=ids,
            bridge=bridge,
            duration=args.duration,
            feedback_interval=args.feedback_interval
        )
    finally:
        # Cleanup
        print("\nStopping components...")
        ids.stop()
        bridge.stop()
        monitor.stop()
        print("All components stopped")


if __name__ == "__main__":
    main() 