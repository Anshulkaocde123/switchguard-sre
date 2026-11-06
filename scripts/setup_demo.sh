#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "==> [1/4] Checking and bootstrapping SwitchGuard Rust AST, Audit & PII Verifier..."
CLI_FOUND=0
if command -v switchguard-cli >/dev/null 2>&1; then
    CLI_FOUND=1
elif [ -x "$HOME/.local/bin/switchguard-cli" ]; then
    CLI_FOUND=1
elif [ -x "$ROOT_DIR/switchguard-cli/target/release/switchguard-cli" ]; then
    CLI_FOUND=1
fi

if [ "$CLI_FOUND" -eq 0 ] || [ "${FORCE_REBUILD:-0}" = "1" ]; then
    echo "==> switchguard-cli not found in PATH, ~/.local/bin, or target/release; building via cargo build --release..."
    cargo build --release -j 2 --manifest-path "$ROOT_DIR/switchguard-cli/Cargo.toml"
fi

mkdir -p "$HOME/.local/bin" "$HOME/.opencode/bin" "$HOME/bin"
if [ -f "$ROOT_DIR/switchguard-cli/target/release/switchguard-cli" ]; then
    cp "$ROOT_DIR/switchguard-cli/target/release/switchguard-cli" "$HOME/.local/bin/switchguard-cli"
    cp "$ROOT_DIR/switchguard-cli/target/release/switchguard-cli" "$HOME/.opencode/bin/switchguard-cli" 2>/dev/null || true
    cp "$ROOT_DIR/switchguard-cli/target/release/switchguard-cli" "$HOME/bin/switchguard-cli" 2>/dev/null || true
    chmod +x "$HOME/.local/bin/switchguard-cli"
fi

echo "==> [2/4] Resetting workspace/sandbox-app to clean baseline state..."
git -C "$ROOT_DIR/workspace/sandbox-app" checkout HEAD -- .
git -C "$ROOT_DIR/workspace/sandbox-app" clean -fd
rm -rf "$ROOT_DIR/workspace/sandbox-app/__pycache__" "$ROOT_DIR/workspace/sandbox-app/.pytest_cache"

echo "==> [3/4] Resetting live telemetry state and clearing lockfiles..."
echo '{"incident_id": null, "current_state": "IDLE", "retry_count": 0, "incidents": {}}' > "$ROOT_DIR/workspace/telemetry/incident_state.json"
echo '{}' > "$ROOT_DIR/workspace/telemetry/dedup_index.json"
rm -f "$ROOT_DIR/workspace/telemetry/.triage.lock" "$ROOT_DIR/workspace/telemetry/dedup_index.lock" "$ROOT_DIR/workspace/telemetry/incident_state.json.tmp"
rm -rf "$ROOT_DIR/workspace/telemetry/__pycache__"

echo "==> [4/4] Verifying baseline pytest suite..."
python3 -m pytest -q "$ROOT_DIR/workspace/sandbox-app/test_cart.py"

echo "================================================================="
echo "==> SwitchGuard SRE Sandbox is 100% READY for clean-room demo! <=="
echo "================================================================="
