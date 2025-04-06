@echo off
echo WinIDS Adaptive IDS with Reinforcement Learning
echo ==============================================
echo.

REM Set default paths and parameters
set MODEL_PATH=..\WinIDS\models\best_fast_model.h5
set NORM_PARAMS_PATH=..\WinIDS\models\normalization_params.json
set RL_MODEL_DIR=..\rl_models
set THRESHOLD=0.7
set DURATION=600
set FEEDBACK_INTERVAL=15

REM Check if Python is installed
python --version > nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo Error: Python is not installed or not in the PATH.
    echo Please install Python 3.6 or later.
    exit /b 1
)

REM Create RL models directory if it doesn't exist
if not exist "%RL_MODEL_DIR%" (
    mkdir "%RL_MODEL_DIR%"
    echo Created directory for RL models: %RL_MODEL_DIR%
)

echo Starting WinIDS with reinforcement learning...
echo.
echo Parameters:
echo - Model path: %MODEL_PATH%
echo - Normalization parameters: %NORM_PARAMS_PATH%
echo - RL model directory: %RL_MODEL_DIR%
echo - Initial threshold: %THRESHOLD%
echo - Duration: %DURATION% seconds
echo - Feedback interval: %FEEDBACK_INTERVAL% seconds
echo.

REM Run the Adaptive IDS example
python ..\examples\adaptive_ids_example.py --model "%MODEL_PATH%" --norm-params "%NORM_PARAMS_PATH%" --rl-model-dir "%RL_MODEL_DIR%" --initial-threshold %THRESHOLD% --duration %DURATION% --feedback-interval %FEEDBACK_INTERVAL%

echo.
echo Finished running Adaptive IDS.
pause 