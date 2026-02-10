#!/bin/bash

# Clone the repository
git clone https://gitee.com/xheishou/termux-x-c2.git

# Enter the directory
cd termux-x-c2 || exit

# Update package list and install dependencies
apt update
apt install curl build-essential mingw-w64 -y

# Install Rust (non-interactive)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y

# Configure environment
source "$HOME/.cargo/env"

# Add Rust target for Windows cross-compilation
rustup target add x86_64-pc-windows-gnu

# Grant execution permissions and run the server in background
chmod +x cupcake-server-linux-amd64
nohup ./cupcake-server-linux-amd64 > /dev/null 2>&1 &
