"""
Test the reinforcement learning components of WinIDS.
"""

import unittest
import os
import tempfile
import json
import numpy as np
import time

try:
    from WinIDS import FastIDS, RL_AVAILABLE
    if RL_AVAILABLE:
        from WinIDS.rl_agent import AdaptiveIDS, DQNAgent, RLEnvironment
except ImportError:
    # Handle the case where the package is not installed
    print("The WinIDS package is not installed. Skipping tests.")
    FastIDS = None
    RL_AVAILABLE = False


@unittest.skipIf(not RL_AVAILABLE, "Reinforcement learning not available")
class RLTest(unittest.TestCase):
    """Test the reinforcement learning components."""

    def setUp(self):
        """Set up the test environment."""
        # Create a temporary directory for RL models
        self.temp_dir = tempfile.TemporaryDirectory()
        self.rl_model_dir = os.path.join(self.temp_dir.name, "rl_models")
        os.makedirs(self.rl_model_dir, exist_ok=True)
        
        # Create dummy model files for FastIDS
        try:
            import tensorflow as tf
            
            # Create simple dummy model for FastIDS
            inputs = tf.keras.Input(shape=(10,))
            outputs = tf.keras.layers.Dense(5, activation='softmax')(inputs)
            model = tf.keras.Model(inputs=inputs, outputs=outputs)
            
            # Save the model
            self.model_path = os.path.join(self.temp_dir.name, "dummy_model.h5")
            model.save(self.model_path)
            
            # Create normalization parameters
            self.norm_params_path = os.path.join(self.temp_dir.name, "norm_params.json")
            norm_params = {
                "mean": [0.0] * 10,
                "std": [1.0] * 10
            }
            with open(self.norm_params_path, "w") as f:
                json.dump(norm_params, f)
                
        except ImportError:
            self.skipTest("TensorFlow not installed")
            
    def tearDown(self):
        """Clean up the test environment."""
        self.temp_dir.cleanup()

    def test_rl_environment(self):
        """Test the reinforcement learning environment."""
        env = RLEnvironment(state_size=10, action_size=5)
        state = env.reset()
        
        self.assertEqual(len(state), 10)
        self.assertEqual(len(env.actions), 5)
        
        # Test step function
        metrics = {
            'total_packets': 100,
            'alerts': 10,
            'true_positives': 8,
            'false_positives': 2,
            'threshold': 0.7
        }
        
        next_state, reward, done, info = env.step(2, metrics)
        
        self.assertEqual(len(next_state), 10)
        self.assertGreaterEqual(reward, 0)  # Reward should be positive for good detection
        self.assertIn('threshold_change', info)

    def test_dqn_agent(self):
        """Test the DQN agent."""
        try:
            agent = DQNAgent(state_size=10, action_size=5, model_dir=self.rl_model_dir)
            
            # Test model creation
            self.assertIsNotNone(agent.model)
            
            # Test action selection
            state = np.random.random(10)
            action = agent.act(state)
            
            self.assertGreaterEqual(action, 0)
            self.assertLess(action, 5)
            
            # Test memory and replay
            agent.remember(state, action, 1.0, state, False)
            self.assertEqual(len(agent.memory), 1)
            
            # Multiple items need to be in memory for replay to work
            for _ in range(32):
                agent.remember(state, action, 1.0, state, False)
                
            agent.replay(batch_size=16)
            
            # Test model saving
            agent.save_model()
            self.assertTrue(os.path.exists(agent.model_path))
            
        except Exception as e:
            self.fail(f"DQNAgent test failed: {str(e)}")

    def test_adaptive_ids(self):
        """Test the AdaptiveIDS class."""
        adaptive_ids = AdaptiveIDS(
            state_size=10,
            action_size=5,
            base_threshold=0.7,
            model_dir=self.rl_model_dir,
            training_mode=True
        )
        
        # Test initial setup
        self.assertEqual(adaptive_ids.threshold, 0.7)
        self.assertIsNotNone(adaptive_ids.environment)
        self.assertIsNotNone(adaptive_ids.agent)
        
        # Test threshold adaptation
        new_threshold, change = adaptive_ids.adapt_threshold(0.85, is_attack=True)
        
        self.assertGreaterEqual(new_threshold, 0.1)
        self.assertLessEqual(new_threshold, 0.99)
        
        # Test metric updates
        metrics = {
            'total_packets': 1000,
            'alerts': 50,
            'true_positives': 45,
            'false_positives': 5
        }
        
        adaptive_ids.update_metrics(metrics)
        self.assertEqual(adaptive_ids.metrics['total_packets'], 1000)
        
        # Test background threads
        adaptive_ids.start_adjustment_thread(interval=1)
        self.assertTrue(adaptive_ids.is_adjusting)
        
        # Wait briefly to let the thread work
        time.sleep(2)
        
        # Stop thread
        adaptive_ids.stop_adjustment_thread()
        self.assertFalse(adaptive_ids.is_adjusting)
        
        # Test state saving and loading
        adaptive_ids.save_state()
        self.assertTrue(os.path.exists(os.path.join(self.rl_model_dir, "adaptive_state.json")))
        
        # Modify threshold to test loading
        old_threshold = adaptive_ids.threshold
        adaptive_ids.threshold = 0.5
        
        # Load state which should restore the threshold
        adaptive_ids.load_state()
        self.assertEqual(adaptive_ids.threshold, old_threshold)

    def test_fastids_with_rl(self):
        """Test FastIDS with reinforcement learning enabled."""
        ids = FastIDS(
            model_path=self.model_path,
            norm_params_path=self.norm_params_path,
            threshold=0.7,
            use_rl=True,
            rl_model_dir=self.rl_model_dir,
            rl_training_mode=True
        )
        
        # Check RL components were initialized
        self.assertTrue(ids.use_rl)
        self.assertIsNotNone(ids.adaptive_ids)
        
        # Test model loading
        self.assertTrue(ids.load_model_files())
        
        # Test stats
        stats = ids.get_stats()
        self.assertIn('threshold', stats)
        self.assertEqual(stats['threshold'], 0.7)
        
        # Test feedback processing
        feedback_data = {
            "type": "feedback",
            "alert_id": "test-alert-1",
            "is_attack": True,
            "confidence": 0.85
        }
        
        # Convert to JSON string as expected by the method
        feedback_json = json.dumps(feedback_data)
        ids._process_traffic_data(feedback_json)
        
        # Verify threshold adaptation works when handling feedback
        # (Exact values will depend on the RL agent's decisions)
        self.assertIsNotNone(ids.threshold)


if __name__ == "__main__":
    unittest.main() 