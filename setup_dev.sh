#!/bin/bash
set -e

echo "Initialising Lanthorn development environment..."

# 1. Install system dependencies (Debian/Ubuntu assumed)
if command -v apt-get &> /dev/null; then
    echo "Installing system dependencies..."
    # Check if we have sudo
    if command -v sudo &> /dev/null; then
        SUDO="sudo"
    else
        SUDO=""
    fi

    $SUDO apt-get update
    $SUDO apt-get install -y build-essential libssl-dev pkg-config llvm clang
else
    echo "Warning: Not on Debian/Ubuntu, skipping system package installation."
    echo "Please ensure you have build-essential, libssl-dev, pkg-config, llvm, and clang installed."
fi

# 2. Install Rust toolchains
echo "Installing Rust toolchains..."
if ! command -v rustup &> /dev/null; then
    echo "Installing rustup..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source $HOME/.cargo/env
fi

# Ensure stable is installed (default)
rustup install stable
rustup default stable

# Install nightly for eBPF compilation
echo "Installing nightly toolchain and rust-src..."
rustup install nightly
rustup component add rust-src --toolchain nightly

# 3. Install bpf-linker
echo "Installing bpf-linker..."
if ! command -v bpf-linker &> /dev/null; then
    cargo install bpf-linker
else
    echo "bpf-linker already installed."
fi

echo "Environment initialisation complete!"
echo "You can now build the project with: cargo build --release"
