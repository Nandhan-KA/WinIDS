"""
Reinforcement Learning Agent for WinIDS

This module implements a reinforcement learning agent that continuously
adapts and improves the intrusion detection system based on feedback.
"""

import numpy as np
import os
import json
import time
from datetime import datetime
import random
import threading

try:
    import tensorflow as tf
    from tensorflow.keras.models import Sequential, load_model, Model
    from tensorflow.keras.layers import Dense, Dropout, Input
    from tensorflow.keras.optimizers import Adam
except ImportError:
    tf = None


class RLEnvironment:
    """Environment for the RL agent to interact with the IDS system."""
    
    def __init__(self, state_size=10, action_size=5):
        """Initialize the RL environment.
        
        Args:
            state_size: Size of the state space (features)
            action_size: Size of the action space (threshold adjustments, etc.)
        """
        self.state_size = state_size
        self.action_size = action_size
        self.reward_history = []
        self.current_state = np.zeros(state_size)
        
        # Define action space (e.g., threshold adjustments)
        self.actions = {
            0: -0.05,  # Decrease threshold significantly
            1: -0.02,  # Decrease threshold slightly
            2: 0.0,    # Keep threshold the same
            3: 0.02,   # Increase threshold slightly
            4: 0.05    # Increase threshold significantly
        }
        
    def reset(self):
        """Reset the environment to initial state."""
        self.current_state = np.zeros(self.state_size)
        return self.current_state
        
    def step(self, action, current_metrics):
        """Take an action in the environment.
        
        Args:
            action: The action to take
            current_metrics: Current system metrics (false positives, true positives, etc.)
            
        Returns:
            next_state: The new state after taking the action
            reward: The reward for the action
            done: Whether the episode is done
            info: Additional information
        """
        # Extract metrics
        false_positives = current_metrics.get('false_positives', 0)
        true_positives = current_metrics.get('true_positives', 0)
        total_packets = current_metrics.get('total_packets', 1)  # Avoid division by zero
        
        # Calculate reward based on performance metrics
        # Reward good detection rates and penalize false positives
        reward = (true_positives / max(1, true_positives + false_positives)) - (false_positives / total_packets)
        
        # Update state with current metrics and action results
        next_state = np.array([
            current_metrics.get('alerts', 0) / max(1, total_packets),
            current_metrics.get('dos_alerts', 0) / max(1, total_packets),
            current_metrics.get('probe_alerts', 0) / max(1, total_packets),
            current_metrics.get('r2l_alerts', 0) / max(1, total_packets),
            current_metrics.get('u2r_alerts', 0) / max(1, total_packets),
            false_positives / max(1, total_packets),
            true_positives / max(1, total_packets),
            current_metrics.get('avg_confidence', 0.5),
            current_metrics.get('threshold', 0.5),
            self.actions[action]  # The action itself (threshold adjustment)
        ])
        
        self.current_state = next_state
        self.reward_history.append(reward)
        
        # For simplicity, episodes don't end
        done = False
        
        # Additional info
        info = {
            'threshold_change': self.actions[action],
            'current_reward': reward,
            'avg_reward': np.mean(self.reward_history[-100:]) if self.reward_history else 0
        }
        
        return next_state, reward, done, info


class DQNAgent:
    """Deep Q-Network Agent for adaptive intrusion detection."""
    
    def __init__(self, state_size, action_size, model_dir="./rl_models"):
        """Initialize the DQN Agent.
        
        Args:
            state_size: Dimension of state space
            action_size: Dimension of action space
            model_dir: Directory to save/load models
        """
        if tf is None:
            raise ImportError("TensorFlow is required for the DQN Agent")
            
        self.state_size = state_size
        self.action_size = action_size
        self.memory = []
        self.gamma = 0.95    # discount rate
        self.epsilon = 1.0   # exploration rate
        self.epsilon_min = 0.01
        self.epsilon_decay = 0.995
        self.learning_rate = 0.001
        self.model_dir = model_dir
        self.model_path = os.path.join(model_dir, "dqn_model.h5")
        self.batch_size = 32
        self.max_memory_size = 2000
        
        # Create directory if it doesn't exist
        if not os.path.exists(model_dir):
            os.makedirs(model_dir)
            
        # Initialize model or load existing
        if os.path.exists(self.model_path):
            self.model = load_model(self.model_path)
            print(f"Loaded RL model from {self.model_path}")
        else:
            self.model = self._build_model()
            print("Created new RL model")
            
        # Training thread control
        self.is_training = False
        self.training_thread = None
        
    def _build_model(self):
        """Build a neural network model for deep Q learning."""
        model = Sequential()
        model.add(Dense(24, input_dim=self.state_size, activation='relu'))
        model.add(Dropout(0.1))
        model.add(Dense(24, activation='relu'))
        model.add(Dropout(0.1))
        model.add(Dense(self.action_size, activation='linear'))
        model.compile(loss='mse', optimizer=Adam(learning_rate=self.learning_rate))
        return model
        
    def remember(self, state, action, reward, next_state, done):
        """Store experience in memory."""
        # Limit memory size to prevent memory issues
        if len(self.memory) >= self.max_memory_size:
            self.memory.pop(0)
        self.memory.append((state, action, reward, next_state, done))
        
    def act(self, state):
        """Choose action based on state using epsilon-greedy policy."""
        if np.random.rand() <= self.epsilon:
            return random.randrange(self.action_size)
        
        state = np.reshape(state, [1, self.state_size])
        act_values = self.model.predict(state, verbose=0)
        return np.argmax(act_values[0])
        
    def replay(self, batch_size=None):
        """Train the model with experiences from memory."""
        if batch_size is None:
            batch_size = self.batch_size
            
        if len(self.memory) < batch_size:
            return
            
        minibatch = random.sample(self.memory, batch_size)
        
        for state, action, reward, next_state, done in minibatch:
            state = np.reshape(state, [1, self.state_size])
            next_state = np.reshape(next_state, [1, self.state_size])
            
            target = reward
            if not done:
                target = reward + self.gamma * np.amax(self.model.predict(next_state, verbose=0)[0])
                
            target_f = self.model.predict(state, verbose=0)
            target_f[0][action] = target
            
            self.model.fit(state, target_f, epochs=1, verbose=0)
            
        if self.epsilon > self.epsilon_min:
            self.epsilon *= self.epsilon_decay
            
    def save_model(self):
        """Save the model to disk."""
        self.model.save(self.model_path)
        print(f"RL model saved to {self.model_path}")
        
    def start_training(self, training_interval=300):
        """Start training in a background thread.
        
        Args:
            training_interval: Seconds between training batches
        """
        if self.is_training:
            return
            
        self.is_training = True
        
        def training_loop():
            while self.is_training:
                if len(self.memory) >= self.batch_size:
                    self.replay()
                    # Save model periodically
                    self.save_model()
                time.sleep(training_interval)
                
        self.training_thread = threading.Thread(target=training_loop, daemon=True)
        self.training_thread.start()
        
    def stop_training(self):
        """Stop the training thread."""
        self.is_training = False
        if self.training_thread:
            self.training_thread.join(timeout=1.0)
            self.save_model()


class AdaptiveIDS:
    """Adaptive IDS system using reinforcement learning."""
    
    def __init__(self, state_size=10, action_size=5, base_threshold=0.7, 
                model_dir="./rl_models", training_mode=True):
        """Initialize the Adaptive IDS.
        
        Args:
            state_size: Size of state space for RL
            action_size: Size of action space for RL
            base_threshold: Initial detection threshold
            model_dir: Directory to save/load RL models
            training_mode: Whether to train the RL model
        """
        self.threshold = base_threshold
        self.base_threshold = base_threshold
        self.metrics = {
            'total_packets': 0,
            'alerts': 0,
            'true_positives': 0,
            'false_positives': 0,
            'dos_alerts': 0,
            'probe_alerts': 0,
            'r2l_alerts': 0,
            'u2r_alerts': 0,
            'avg_confidence': 0.5,
            'threshold': base_threshold
        }
        
        # Initialize RL components
        self.environment = RLEnvironment(state_size=state_size, action_size=action_size)
        self.agent = DQNAgent(state_size=state_size, action_size=action_size, model_dir=model_dir)
        self.current_state = self.environment.reset()
        self.training_mode = training_mode
        
        if training_mode:
            self.agent.start_training()
            
        # Threshold adjustment thread
        self.adjustment_thread = None
        self.is_adjusting = False
        
    def update_metrics(self, metrics_update):
        """Update internal metrics with new data."""
        for key, value in metrics_update.items():
            if key in self.metrics:
                self.metrics[key] = value
                
    def adapt_threshold(self, current_confidence, is_attack=None):
        """Adapt threshold based on RL agent decision."""
        # Get current state
        state = np.array([
            self.metrics.get('alerts', 0) / max(1, self.metrics.get('total_packets', 1)),
            self.metrics.get('dos_alerts', 0) / max(1, self.metrics.get('total_packets', 1)),
            self.metrics.get('probe_alerts', 0) / max(1, self.metrics.get('total_packets', 1)),
            self.metrics.get('r2l_alerts', 0) / max(1, self.metrics.get('total_packets', 1)),
            self.metrics.get('u2r_alerts', 0) / max(1, self.metrics.get('total_packets', 1)),
            self.metrics.get('false_positives', 0) / max(1, self.metrics.get('total_packets', 1)),
            self.metrics.get('true_positives', 0) / max(1, self.metrics.get('total_packets', 1)),
            self.metrics.get('avg_confidence', 0.5),
            self.threshold,
            0.0  # Placeholder for action
        ])
        
        # Get action from agent
        action = self.agent.act(state)
        
        # Apply action (adjust threshold)
        threshold_change = self.environment.actions[action]
        new_threshold = max(0.1, min(0.99, self.threshold + threshold_change))
        
        old_threshold = self.threshold
        self.threshold = new_threshold
        self.metrics['threshold'] = new_threshold
        
        # If we know whether this is an attack, use it for feedback
        if is_attack is not None:
            # Get next state and reward
            is_alert = current_confidence >= self.threshold
            
            # Update metrics for feedback
            if is_attack and is_alert:
                self.metrics['true_positives'] += 1
            elif not is_attack and is_alert:
                self.metrics['false_positives'] += 1
                
            next_state, reward, done, info = self.environment.step(action, self.metrics)
            
            # Remember this experience for training
            if self.training_mode:
                self.agent.remember(state, action, reward, next_state, done)
                
            self.current_state = next_state
            
        return new_threshold, threshold_change
        
    def start_adjustment_thread(self, interval=60):
        """Start threshold adjustment in a background thread.
        
        Args:
            interval: Seconds between threshold adjustments
        """
        if self.is_adjusting:
            return
            
        self.is_adjusting = True
        
        def adjustment_loop():
            while self.is_adjusting:
                # Adjust threshold based on current metrics
                self.adapt_threshold(self.metrics.get('avg_confidence', 0.5))
                time.sleep(interval)
                
        self.adjustment_thread = threading.Thread(target=adjustment_loop, daemon=True)
        self.adjustment_thread.start()
        
    def stop_adjustment_thread(self):
        """Stop the threshold adjustment thread."""
        self.is_adjusting = False
        if self.adjustment_thread:
            self.adjustment_thread.join(timeout=1.0)
            
    def stop(self):
        """Stop all background threads."""
        self.stop_adjustment_thread()
        if self.training_mode:
            self.agent.stop_training()
            
    def save_state(self):
        """Save the current state of the adaptive IDS."""
        # Save RL model
        self.agent.save_model()
        
        # Save additional state if needed
        state_path = os.path.join(self.agent.model_dir, "adaptive_state.json")
        state = {
            "threshold": self.threshold,
            "base_threshold": self.base_threshold,
            "metrics": self.metrics,
            "timestamp": datetime.now().isoformat()
        }
        
        with open(state_path, 'w') as f:
            json.dump(state, f, indent=2)
            
        print(f"Adaptive IDS state saved to {state_path}")
        
    def load_state(self):
        """Load the saved state of the adaptive IDS."""
        state_path = os.path.join(self.agent.model_dir, "adaptive_state.json")
        
        if os.path.exists(state_path):
            with open(state_path, 'r') as f:
                state = json.load(f)
                
            self.threshold = state.get("threshold", self.base_threshold)
            self.base_threshold = state.get("base_threshold", self.base_threshold)
            self.metrics = state.get("metrics", self.metrics)
            
            print(f"Loaded Adaptive IDS state from {state_path}")
            return True
        return False 