#!/bin/bash

echo "WinIDS Adaptive IDS with Reinforcement Learning"
echo "=============================================="
echo

# Set default paths and parameters
MODEL_PATH="../WinIDS/models/best_fast_model.h5"
NORM_PARAMS_PATH="../WinIDS/models/normalization_params.json"
RL_MODEL_DIR="../rl_models"
THRESHOLD=0.7
DURATION=600
FEEDBACK_INTERVAL=15

# Check if Python is installed
if ! command -v python3 &> /dev/null; then
    echo "Error: Python 3 is not installed or not in the PATH."
    echo "Please install Python 3.6 or later."
    exit 1
fi

# Create RL models directory if it doesn't exist
if [ ! -d "$RL_MODEL_DIR" ]; then
    mkdir -p "$RL_MODEL_DIR"
    echo "Created directory for RL models: $RL_MODEL_DIR"
fi

echo "Starting WinIDS with reinforcement learning..."
echo
echo "Parameters:"
echo "- Model path: $MODEL_PATH"
echo "- Normalization parameters: $NORM_PARAMS_PATH"
echo "- RL model directory: $RL_MODEL_DIR"
echo "- Initial threshold: $THRESHOLD"
echo "- Duration: $DURATION seconds"
echo "- Feedback interval: $FEEDBACK_INTERVAL seconds"
echo

# Run the Adaptive IDS example
python3 ../examples/adaptive_ids_example.py \
    --model "$MODEL_PATH" \
    --norm-params "$NORM_PARAMS_PATH" \
    --rl-model-dir "$RL_MODEL_DIR" \
    --initial-threshold $THRESHOLD \
    --duration $DURATION \
    --feedback-interval $FEEDBACK_INTERVAL

echo
echo "Finished running Adaptive IDS."
read -p "Press Enter to continue..." 