#!/bin/bash
# Recon Tool v3 Launcher Script

# Get the directory where this script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"

# Change to the recon-tool-v3 directory
cd "$SCRIPT_DIR"

# Activate virtual environment and run the tool
source .venv/bin/activate && python main.py "$@"
