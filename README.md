# WinIDS - Windows Intrusion Detection System

A machine learning and reinforcement learning-based intrusion detection system designed for Windows environments with real-time monitoring capabilities.

[![PyPI version](https://badge.fury.io/py/WinIDS.svg)](https://badge.fury.io/py/WinIDS)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Features

- 🔍 Real-time network traffic monitoring
- 🧠 Neural network-based intrusion detection
- 🤖 Reinforcement learning for adaptive thresholds
- 🚨 Detect multiple attack types: DOS, Probe, R2L, U2R
- 📊 Professional dashboard with visualizations
- 🛡️ Traffic generation and simulation capabilities
- 🔄 Bridge and Monitor components for flexible deployment
- 📈 Self-learning capabilities through RL feedback

## Installation

### From PyPI

```bash
pip install WinIDS
```

### From Source

```bash
git clone https://github.com/yourusername/WinIDS.git
cd WinIDS
pip install -e .
```

## Quick Start

WinIDS provides both command-line tools and Python library components.

### Using Command-line Tools

1. **Start the Monitor**:

   ```bash
   WinIDS-monitor --host localhost --port 5000
   ```

2. **Start the Bridge** (traffic generator):

   ```bash
   WinIDS-bridge --monitor-host localhost --monitor-port 5000
   ```

3. **Launch the Dashboard**:

   ```bash
   WinIDS-dashboard
   ```

4. **Test with Attack Panel** (optional):

   ```bash
   WinIDS-attack-panel
   ```

### Using as a Python Library

```python
from WinIDS import FastIDS, IDSBridge, IDSMonitor

# Create and start the monitor
monitor = IDSMonitor(host="localhost", port=5000)
monitor.start()

# Create and start the bridge
bridge = IDSBridge(monitor_host="localhost", monitor_port=5000)
bridge.start()

# Create and start the IDS with reinforcement learning
ids = FastIDS(model_path="models/best_fast_model.h5", 
             norm_params_path="models/normalization_params.json",
             use_rl=True)
ids.connect_to_bridge()
ids.start()

# Get current stats
stats = ids.get_stats()
print(f"Uptime: {stats['uptime']}s, Packets: {stats['total_packets']}, Alerts: {stats['alerts']}")

# Stop components when done
ids.stop()
bridge.stop()
monitor.stop()
```

## Components

### FastIDS

The core intrusion detection engine using neural network models with reinforcement learning capabilities.

```python
from WinIDS import FastIDS

ids = FastIDS(
    model_path="models/best_fast_model.h5",
    norm_params_path="models/normalization_params.json",
    threshold=0.7,
    bridge_host="localhost",
    bridge_port=5000,
    use_rl=True,
    rl_model_dir="./rl_models",
    rl_training_mode=True
)
```

### IDSMonitor

Connection manager between the bridge and the IDS system.

```python
from WinIDS import IDSMonitor

monitor = IDSMonitor(
    host="localhost",
    port=5000,
    check_interval=1.0,
    traffic_file="data/traffic_log.json",
    disable_attacks=False
)
```

### IDSBridge

Traffic generator that connects to the monitor.

```python
from WinIDS import IDSBridge

bridge = IDSBridge(
    monitor_host="localhost",
    monitor_port=5000,
    data_file="data/training_data.csv",
    synthetic=True
)
```

### ProDashboard

Graphical user interface for the IDS system.

```python
from WinIDS import ProDashboard, FastIDS

ids = FastIDS(model_path="models/best_fast_model.h5", use_rl=True)
dashboard = ProDashboard(ids, dark_mode=True)
dashboard.run()
```

### AttackPanel

Tool for generating test attacks.

```python
from WinIDS import AttackPanel

panel = AttackPanel(
    bridge_host="localhost",
    bridge_port=5000,
    dark_mode=True
)
panel.run()
```

## Reinforcement Learning

WinIDS uses reinforcement learning to continuously adapt and optimize its detection capabilities:

### Adaptive Thresholds

The RL agent automatically adjusts detection thresholds based on:
- Historical attack patterns
- False positive rates
- System performance

```python
from WinIDS import FastIDS

# Create an IDS with reinforcement learning enabled
ids = FastIDS(
    model_path="models/best_fast_model.h5",
    use_rl=True,
    rl_model_dir="./custom_rl_models"
)

# RL will automatically adjust thresholds based on traffic patterns
ids.start()
```

### Feedback Mechanism

You can provide explicit feedback to improve detection:

```python
# Example of providing feedback to the RL system
feedback = {
    "alert_id": "alert-1234",
    "is_attack": True,  # True if this was indeed an attack, False if false positive
    "confidence": 0.85
}

# Send feedback (handled internally by the IDS)
bridge.send_feedback(feedback)
```

### Custom RL Model Directory

Specify where to store trained RL models:

```bash
WinIDS-dashboard --rl-model-dir /path/to/rl_models
```

## Attack Simulation

WinIDS includes an attack simulator for testing the IDS system:

```python
from WinIDS.attack_simulator import simulate_attack

# Simulate a DOS attack with 75% intensity for 10 seconds
attack_data = simulate_attack(attack_type="dos", intensity=0.75, duration=10)

# Simulate a probe attack
probe_attack = simulate_attack(attack_type="probe", intensity=0.5, duration=5)
```

## Training Custom Models

WinIDS provides scripts for training custom models:

```bash
python -m WinIDS.scripts.train_model --dataset your_data.csv --model-output models/custom_model.h5
```

## Command-line Options

### WinIDS-dashboard

```
usage: WinIDS-dashboard [-h] [--model MODEL] [--norm-params NORM_PARAMS]
                        [--threshold THRESHOLD] [--bridge-host BRIDGE_HOST]
                        [--bridge-port BRIDGE_PORT] [--light-mode]
                        [--disable-attacks] [--disable-rl]
                        [--rl-model-dir RL_MODEL_DIR] [--disable-rl-training]
```

### WinIDS-bridge

```
usage: WinIDS-bridge [-h] [--monitor-host MONITOR_HOST]
                     [--monitor-port MONITOR_PORT] [--interval INTERVAL]
                     [--synthetic] [--data-file DATA_FILE]
```

### WinIDS-monitor

```
usage: WinIDS-monitor [-h] [--host HOST] [--port PORT]
                      [--check-interval CHECK_INTERVAL]
                      [--traffic-file TRAFFIC_FILE] [--disable-attacks]
```

### WinIDS-attack-panel

```
usage: WinIDS-attack-panel [-h] [--bridge-host BRIDGE_HOST]
                           [--bridge-port BRIDGE_PORT] [--light-mode]
```

## How Reinforcement Learning Works in WinIDS

WinIDS implements a Deep Q-Network (DQN) approach to optimize intrusion detection:

1. **State**: The current system state includes metrics like false positive rate, attack distribution, and current threshold.
   
2. **Actions**: The RL agent can adjust detection thresholds up or down with varying degrees.

3. **Rewards**: The system receives rewards for:
   - Successfully detecting real attacks
   - Avoiding false positives
   - Maintaining an optimal balance between security and performance

4. **Training**: The agent continuously learns from interactions with the network traffic and feedback.

5. **Adaptation**: The system automatically adjusts to changing network conditions and attack patterns.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Acknowledgements

- Special thanks to all contributors
- Built with TensorFlow, NumPy, and other open-source libraries 