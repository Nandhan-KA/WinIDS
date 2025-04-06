#!/usr/bin/env python
"""
Create dummy model and normalization parameters for testing the WinIDS system.
"""

import os
import json
import numpy as np

try:
    import tensorflow as tf
    from tensorflow.keras.models import Sequential
    from tensorflow.keras.layers import Dense
except ImportError:
    print("Error: TensorFlow is required. Please install it with 'pip install tensorflow'.")
    exit(1)

# Create models directory if it doesn't exist
os.makedirs("models", exist_ok=True)

# Create a simple model for testing
model = Sequential([
    Dense(32, input_shape=(41,), activation='relu'),
    Dense(16, activation='relu'),
    Dense(5, activation='softmax')  # 5 outputs: normal, dos, probe, r2l, u2r
])

# Compile the model
model.compile(optimizer='adam', loss='categorical_crossentropy', metrics=['accuracy'])

# Save the model
model_path = os.path.join("models", "best_fast_model.h5")
model.save(model_path)
print(f"Dummy model saved to {model_path}")

# Create normalization parameters (means and standard deviations for features)
# In a real scenario, these would be calculated from training data
norm_params = {
    "mean": [0.0] * 41,
    "std": [1.0] * 41
}

# Save normalization parameters
norm_params_path = os.path.join("models", "normalization_params.json")
with open(norm_params_path, "w") as f:
    json.dump(norm_params, f, indent=2)
print(f"Normalization parameters saved to {norm_params_path}")

print("\nDummy model and normalization parameters have been created for testing.")
print("You can now run the adaptive_ids_example.py with these files.") 