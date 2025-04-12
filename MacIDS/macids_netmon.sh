#!/bin/bash

# macids_netmon.sh - MacIDS Network Monitor Launcher
# This script launches the MacIDS Network Monitor with appropriate permissions

# Check if running with sudo/root
if [ "$EUID" -ne 0 ]; then
  echo "MacIDS Network Analyzer"
  echo "-------------------------------------"
  echo "This application requires administrator privileges."
  echo "Please enter your password when prompted."
  echo ""
  
  # Re-launch with sudo
  sudo "$0" "$@"
  exit $?
fi

echo "MacIDS Network Analyzer"
echo "-------------------------------------"
echo "Starting with administrator privileges..."

# Get the directory where this script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

# Try to run the module (with both capitalization options)
echo "Launching Network Analyzer..."

# First try uppercase module path (as requested by user)
python3 -m MacIDS.netmon 2>/dev/null
if [ $? -ne 0 ]; then
  echo "Trying alternative module path..."
  # Fall back to lowercase if uppercase fails
  python3 -m macids.netmon
fi

# If we get here, monitor has stopped
echo "MacIDS Network Monitor has stopped."
echo "Press Enter to exit..."
read 