# WinIDS Examples

This directory contains example scripts demonstrating how to use the WinIDS system.

## Available Examples

### Adaptive IDS Example

[adaptive_ids_example.py](adaptive_ids_example.py) - Demonstrates how to use the reinforcement learning capabilities of WinIDS to create an adaptive intrusion detection system.

```bash
# Run with default settings
python adaptive_ids_example.py

# Custom settings
python adaptive_ids_example.py --model ../WinIDS/models/best_fast_model.h5 --initial-threshold 0.75 --duration 600
```

This example:
1. Starts a complete WinIDS system with monitor, bridge, and IDS components
2. Enables reinforcement learning for adaptive threshold adjustment
3. Simulates traffic and user feedback to demonstrate how the RL agent adapts
4. Displays real-time statistics of threshold changes and detection performance

## Running the Examples

Make sure you have installed WinIDS first:

```bash
# Install WinIDS from source
cd ..
pip install -e .
```

The examples require all dependencies to be installed and may need administrative privileges to access network interfaces.

## Creating Your Own Examples

Feel free to use these examples as templates for your own use cases. The most important components to understand are:

- `FastIDS` - Core detection engine with RL capabilities
- `IDSMonitor` - Connection manager
- `IDSBridge` - Traffic generator and bridge
- `AdaptiveIDS` - Reinforcement learning component for adaptive behavior 