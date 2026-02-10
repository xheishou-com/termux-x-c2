#!/bin/bash

# Update package list and install dependencies only if missing
if ! command -v curl &> /dev/null || ! command -v x86_64-w64-mingw32-gcc &> /dev/null; then
    echo "Installing system dependencies..."
    apt install curl build-essential mingw-w64 -y
fi

# Install Rust (non-interactive) only if missing
if ! command -v rustc &> /dev/null; then
    echo "Installing Rust..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
else
    # Ensure env is loaded
    if [ -f "$HOME/.cargo/env" ]; then
        source "$HOME/.cargo/env"
    fi
fi

# Add Rust target for Windows cross-compilation only if missing (Idempotent check)
if command -v rustup &> /dev/null; then
    if ! rustup target list --installed | grep -q "x86_64-pc-windows-gnu"; then
        echo "Adding Rust target for Windows (x86_64-pc-windows-gnu)..."
        rustup target add x86_64-pc-windows-gnu
    fi
fi

# Detect architecture and run appropriate server binary
ARCH=$(uname -m)
if [ "$ARCH" = "x86_64" ]; then
    SERVER_BIN="cupcake-server-linux-amd64"
elif [ "$ARCH" = "aarch64" ]; then
    SERVER_BIN="cupcake-server-linux-arm64"
else
    echo "Unsupported architecture: $ARCH"
    exit 1
fi

echo "Detected architecture: $ARCH, using binary: $SERVER_BIN"

# Grant execution permissions and run the server in background
chmod +x "$SERVER_BIN"
nohup ./$SERVER_BIN > /dev/null 2>&1 &
