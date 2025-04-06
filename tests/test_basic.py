import unittest
import os
import tempfile
import json
import numpy as np

try:
    from WinIDS import FastIDS
except ImportError:
    # Handle the case where the package is not installed
    print("The WinIDS package is not installed. Skipping tests.")
    FastIDS = None


@unittest.skipIf(FastIDS is None, "WinIDS package not installed")
class BasicTest(unittest.TestCase):
    """Basic tests for the WinIDS package."""

    def setUp(self):
        """Set up the test environment."""
        # Create a dummy model file
        self.temp_dir = tempfile.TemporaryDirectory()
        
        # Create a simple dummy model that returns predictable results
        try:
            import tensorflow as tf
            
            # Very simple model that just outputs 0.8 for any input
            inputs = tf.keras.Input(shape=(10,))
            outputs = tf.keras.layers.Dense(1, activation='sigmoid')(inputs)
            model = tf.keras.Model(inputs=inputs, outputs=outputs)
            
            # Set weights to output a fixed value
            weights = [np.zeros((10, 1)), np.array([0.8])]
            model.set_weights(weights)
            
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

    def test_init(self):
        """Test initializing the FastIDS class."""
        ids = FastIDS(
            model_path=self.model_path,
            norm_params_path=self.norm_params_path,
            threshold=0.7
        )
        self.assertIsNotNone(ids)
        self.assertEqual(ids.threshold, 0.7)

    def test_process_features(self):
        """Test processing features."""
        ids = FastIDS(
            model_path=self.model_path,
            norm_params_path=self.norm_params_path,
            threshold=0.7
        )
        
        # Create sample features
        features = [0.1] * 10
        
        # Process (this would go through model prediction in a real scenario)
        # In our mock setup, this should return a high confidence value
        traffic_data = {
            "features": features,
            "attack_type": "dos",
            "timestamp": "2023-04-07 12:34:56"
        }
        
        # Directly call the processing method
        # Since we're using a dummy model that outputs 0.8, 
        # this should trigger an alert as it's above our threshold of 0.7
        ids._process_traffic_data(traffic_data)
        
        # Check that stats were updated
        self.assertEqual(ids.stats['total_packets'], 1)
        # Alert should be triggered (confidence 0.8 > threshold 0.7)
        self.assertEqual(ids.stats['alerts'], 1)


if __name__ == "__main__":
    unittest.main() 