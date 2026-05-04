#!/usr/bin/env bash
# =============================================================================
# PhantomVault v1.0 — check_env.sh
# Verifies the development environment is correctly configured.
# Run before starting a coding session or to diagnose problems.
# =============================================================================

set -uo pipefail

PASS=0
FAIL=0
WARN=0

pass() { echo "  [✓] $1"; ((PASS++)) || true; }
fail() { echo "  [✗] $1"; ((FAIL++)) || true; }
warn() { echo "  [!] $1"; ((WARN++)) || true; }

echo ""
echo "=== PhantomVault Environment Check ==="
echo ""

# ── Shell ─────────────────────────────────────────────────────────────────────
echo "Shell:"
CURRENT_SHELL=$(echo $SHELL)
if [[ "$CURRENT_SHELL" == *"zsh"* ]] || [[ "$CURRENT_SHELL" == *"bash"* ]]; then
    pass "Shell: $CURRENT_SHELL"
else
    warn "Unknown shell: $CURRENT_SHELL"
fi

# ── Python ────────────────────────────────────────────────────────────────────
echo ""
echo "Python:"
if command -v python3 &>/dev/null; then
    PY_VERSION=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
    PY_MAJOR=$(python3 -c "import sys; print(sys.version_info.major)")
    PY_MINOR=$(python3 -c "import sys; print(sys.version_info.minor)")
    if [ "$PY_MAJOR" -ge 3 ] && [ "$PY_MINOR" -ge 11 ]; then
        pass "Python $PY_VERSION (>= 3.11 required)"
    else
        fail "Python $PY_VERSION — need 3.11 or later"
    fi
else
    fail "Python 3 not found"
fi

# ── Virtual environment ───────────────────────────────────────────────────────
echo ""
echo "Virtual environment:"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
VENV_DIR="$PROJECT_ROOT/.venv"

if [ -d "$VENV_DIR" ]; then
    pass "Virtual environment exists: $VENV_DIR"
else
    fail "Virtual environment not found at $VENV_DIR — run setup.sh"
fi

if [[ "${VIRTUAL_ENV:-}" == *".venv"* ]]; then
    pass "Virtual environment is active"
else
    warn "Virtual environment not active — run: source .venv/bin/activate"
fi

# ── Rust ─────────────────────────────────────────────────────────────────────
echo ""
echo "Rust toolchain:"
if command -v rustc &>/dev/null; then
    RUST_VER=$(rustc --version | awk '{print $2}')
    pass "rustc $RUST_VER"
else
    fail "rustc not found — install via: curl https://sh.rustup.rs | sh"
fi

if command -v cargo &>/dev/null; then
    CARGO_VER=$(cargo --version | awk '{print $2}')
    pass "cargo $CARGO_VER"
else
    fail "cargo not found"
fi

if rustup toolchain list 2>/dev/null | grep -q "nightly"; then
    pass "nightly toolchain installed"
else
    warn "nightly toolchain not installed — run: rustup toolchain install nightly"
fi

# ── Maturin ───────────────────────────────────────────────────────────────────
echo ""
echo "Maturin:"
if command -v maturin &>/dev/null; then
    MATURIN_VER=$(maturin --version 2>/dev/null | awk '{print $2}')
    if [[ "$MATURIN_VER" == "1.7"* ]]; then
        pass "maturin $MATURIN_VER (correct version)"
    else
        warn "maturin $MATURIN_VER — recommend 1.7.4 (run: cargo install maturin --version 1.7.4 --locked --force)"
    fi
else
    fail "maturin not found — run: cargo install maturin --version 1.7.4 --locked"
fi

# ── Cargo tools ───────────────────────────────────────────────────────────────
echo ""
echo "Cargo tools:"
command -v cargo-fuzz &>/dev/null && pass "cargo-fuzz installed" || warn "cargo-fuzz not installed — run: cargo install cargo-fuzz"
command -v cargo-deny &>/dev/null && pass "cargo-deny installed" || warn "cargo-deny not installed — run: cargo install cargo-deny"

# ── Memory lock ───────────────────────────────────────────────────────────────
echo ""
echo "Memory configuration:"
MEMLOCK=$(ulimit -l 2>/dev/null || echo "unknown")
if [ "$MEMLOCK" = "unlimited" ]; then
    pass "RLIMIT_MEMLOCK = unlimited"
else
    warn "RLIMIT_MEMLOCK = $MEMLOCK (should be unlimited — see setup.sh)"
fi

# ── Swap ─────────────────────────────────────────────────────────────────────
SWAP=$(swapon --show 2>/dev/null || true)
if [ -z "$SWAP" ]; then
    pass "Swap is disabled"
else
    warn "Swap is active — keys may be swappable (sudo swapoff -a)"
fi

# ── Rust build ────────────────────────────────────────────────────────────────
echo ""
echo "Rust build check:"
cd "$PROJECT_ROOT"
if cargo check --manifest-path phantom_core/Cargo.toml 2>&1 | grep -q "Finished"; then
    pass "cargo check passes"
else
    fail "cargo check failed — check errors above"
fi

# ── Python import ─────────────────────────────────────────────────────────────
echo ""
echo "Python module check:"
if python3 -c "from phantomvault import phantom_core" 2>/dev/null; then
    pass "phantom_core imports successfully"
else
    warn "phantom_core import failed — run: maturin develop"
fi

# ── Summary ───────────────────────────────────────────────────────────────────
echo ""
echo "====================================="
echo "  Results: $PASS passed | $WARN warnings | $FAIL failed"
echo "====================================="

if [ "$FAIL" -gt 0 ]; then
    echo "  Run scripts/setup.sh to fix failed checks."
    exit 1
elif [ "$WARN" -gt 0 ]; then
    echo "  Warnings detected but environment is usable."
    exit 0
else
    echo "  All checks passed. Environment is ready."
    exit 0
fi
