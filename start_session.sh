#!/bin/bash

# PhantomVault development session startup
# Run this at the start of every coding session:
#   bash ~/phantomvault/start_session.sh

set -e

echo ""
echo "==================================================="
echo "  PhantomVault v1.0 Development Session"
echo "==================================================="
echo ""

# Go to project root
cd ~/phantomvault

# Activate virtual environment
source .venv/bin/activate

# Load Rust environment
source "$HOME/.cargo/env"

# Set development environment variables
export RUST_BACKTRACE=1
export RUST_LOG=info
export LIBCLANG_PATH=/usr/lib/llvm-$(llvm-config --version 2>/dev/null | cut -d. -f1)/lib

echo "Environment:"
echo "  Python : $(python3 --version)"
echo "  Rust   : $(rustc --version)"
echo "  Cargo  : $(cargo --version)"
echo "  Maturin: $(maturin --version)"
echo "  Venv   : ACTIVE (.venv)"
echo "  Dir    : $(pwd)"
echo ""

echo "System status:"
SWAP=$(swapon --show 2>/dev/null)
if [ -z "$SWAP" ]; then
    echo "  Swap   : DISABLED (good)"
else
    echo "  Swap   : ACTIVE (warning: keys may be swappable)"
fi

MEMLOCK=$(ulimit -l)
if [ "$MEMLOCK" = "unlimited" ]; then
    echo "  mlock  : unlimited (good)"
else
    echo "  mlock  : $MEMLOCK KB (warning: may be too low)"
fi
echo ""

echo "Quick commands:"
echo "  cargo check --manifest-path phantom_core/Cargo.toml"
echo "  cargo test --manifest-path phantom_core/Cargo.toml -- --test-threads=1"
echo "  cargo clippy --manifest-path phantom_core/Cargo.toml -- -D warnings"
echo "  maturin develop"
echo "  cargo +nightly fuzz run fuzz_crypto"
echo ""
echo "==================================================="
echo "  Ready to code"
echo "==================================================="
echo ""
