#!/usr/bin/env bash
# =============================================================================
# PhantomVault v1.0 — setup.sh
# Complete system setup for development and deployment.
# Run once. Persists across reboots.
# =============================================================================

set -euo pipefail

echo ""
echo "=== PhantomVault v1.0 Setup ==="
echo ""

# ── OS Detection ──────────────────────────────────────────────────────────────
OS="$(uname -s)"
echo "Detected OS: $OS"

# ── System packages (Linux/Kali/Debian/Ubuntu) ─────────────────────────────
if [ "$OS" = "Linux" ]; then
    echo ""
    echo "Installing system packages..."
    sudo apt-get update -qq
    sudo apt-get install -y \
        python3 python3-dev python3-pip python3-venv python3-full \
        build-essential pkg-config \
        libssl-dev libffi-dev libgmp-dev \
        git curl wget \
        cryptsetup cryptsetup-bin libcryptsetup-dev \
        clang llvm llvm-dev libclang-dev cmake \
        gcc g++ libc6-dev \
        procps
    echo "System packages installed."
fi

# ── Rust toolchain ────────────────────────────────────────────────────────────
echo ""
if command -v rustc &>/dev/null; then
    echo "Rust already installed: $(rustc --version)"
else
    echo "Installing Rust via rustup..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
    source "$HOME/.cargo/env"
fi

# Ensure nightly for fuzzing
echo "Installing Rust nightly toolchain..."
rustup toolchain install nightly --allow-downgrade
rustup component add rust-src --toolchain nightly

# ── Rust tools ────────────────────────────────────────────────────────────────
echo ""
echo "Installing Rust tools..."

if ! command -v cargo-fuzz &>/dev/null; then
    cargo install cargo-fuzz
    echo "  cargo-fuzz installed"
else
    echo "  cargo-fuzz already installed"
fi

if ! command -v cargo-deny &>/dev/null; then
    cargo install cargo-deny
    echo "  cargo-deny installed"
else
    echo "  cargo-deny already installed"
fi

if ! command -v maturin &>/dev/null; then
    cargo install maturin --version "1.7.4" --locked
    echo "  maturin 1.7.4 installed"
else
    echo "  maturin already installed: $(maturin --version)"
fi

# ── Memory lock limit ─────────────────────────────────────────────────────────
echo ""
echo "Configuring memory lock limit..."
CURRENT_USER=$(whoami)

if [ "$OS" = "Linux" ]; then
    LIMITS_FILE="/etc/security/limits.conf"
    if ! grep -q "phantomvault-memlock" "$LIMITS_FILE" 2>/dev/null; then
        echo "" | sudo tee -a "$LIMITS_FILE" > /dev/null
        echo "# PhantomVault — memory locking for key material" | sudo tee -a "$LIMITS_FILE" > /dev/null
        echo "$CURRENT_USER    soft    memlock    unlimited    # phantomvault-memlock" | sudo tee -a "$LIMITS_FILE" > /dev/null
        echo "$CURRENT_USER    hard    memlock    unlimited    # phantomvault-memlock" | sudo tee -a "$LIMITS_FILE" > /dev/null
        echo "  Added memlock=unlimited for $CURRENT_USER"
        echo "  Log out and back in for this to take effect."
    else
        echo "  memlock limit already configured."
    fi

    PAM_FILE="/etc/pam.d/common-session"
    if ! grep -q "pam_limits.so" "$PAM_FILE" 2>/dev/null; then
        echo "session required pam_limits.so" | sudo tee -a "$PAM_FILE" > /dev/null
        echo "  Added pam_limits.so to $PAM_FILE"
    fi
fi

# ── Python virtual environment ─────────────────────────────────────────────────
echo ""
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

echo "Setting up Python virtual environment at $PROJECT_ROOT/.venv..."
cd "$PROJECT_ROOT"

if [ ! -d ".venv" ]; then
    python3 -m venv .venv
    echo "  Virtual environment created."
fi

source .venv/bin/activate
pip install --upgrade pip setuptools wheel -q

echo "  Installing Python dependencies..."
pip install \
    "maturin==1.7.4" \
    typer rich pyotp qrcode Pillow \
    pytest pytest-cov black ruff mypy \
    -q

echo "  Python dependencies installed."

# ── Build the Rust extension ───────────────────────────────────────────────────
echo ""
echo "Building Rust TCB extension (first build takes a few minutes)..."
maturin develop 2>&1 | tail -5
echo "  Build complete."

# ── Swap disable (optional) ───────────────────────────────────────────────────
echo ""
SWAP=$(swapon --show 2>/dev/null || true)
if [ -n "$SWAP" ]; then
    echo "WARNING: Swap is currently active."
    echo "  For maximum security, disable swap:"
    echo "  sudo swapoff -a"
    echo "  Then comment out swap lines in /etc/fstab"
fi

# ── Test directories ──────────────────────────────────────────────────────────
echo ""
echo "Creating test directories..."
mkdir -p ~/phantomvault_test/{demo_files,empty_dir,mixed_files,large_files,vault_outputs}
mkdir -p ~/phantomvault_test/demo_files/{work,personal}
mkdir -p ~/phantomvault_test/mixed_files/{subdir_a,subdir_b}

if [ ! -f ~/phantomvault_test/demo_files/document_one.txt ]; then
    echo "Sample document one." > ~/phantomvault_test/demo_files/document_one.txt
    echo "Sample document two." > ~/phantomvault_test/demo_files/document_two.txt
    echo "Work report alpha." > ~/phantomvault_test/demo_files/work/report_alpha.txt
    echo "Personal diary entry." > ~/phantomvault_test/demo_files/personal/diary.txt
    echo "  Test files created."
fi

echo ""
echo "============================================="
echo "  Setup complete!"
echo "============================================="
echo ""
echo "To start a development session:"
echo "  bash ~/phantomvault/start_session.sh"
echo ""
echo "To verify everything works:"
echo "  bash ~/phantomvault/scripts/check_env.sh"
echo ""
