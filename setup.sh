#!/bin/bash

# Ensure the script is run as root
if [ "$(id -u)" -ne 0 ]; then
    echo "Please run this script as root (use sudo)"
    exit 1
fi

# Set non-interactive mode to avoid prompts during installation
export DEBIAN_FRONTEND=noninteractive

echo "Installing necessary packages..."
pip install --upgrade pip
pip install Automat
pip install twisted
pip install ltprotocol

CURRENT_DIR=$(pwd)
echo "$CURRENT_DIR"
cd /home/mininet/pox
git checkout angler

cd "$CURRENT_DIR"
echo "Configuring POX module..."
cd pox_module
sudo python2 setup.py develop
cd ../

ln -s -f /home/mininet/pox pox

pkill -9 sr_solution
pkill -9 sr

echo "Setup completed successfully!"
