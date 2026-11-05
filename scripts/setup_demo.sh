#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
echo "==> [1/3] Building & installing SwitchGuard Rust AST, Audit & PII Verifier..."
(cd "$ROOT_DIR/switchguard-cli" && cargo build --release -q)
mkdir -p "$HOME/.local/bin" "$HOME/.opencode/bin" "$HOME/bin"
cp "$ROOT_DIR/switchguard-cli/target/release/switchguard-cli" "$HOME/.local/bin/switchguard-cli"
cp "$ROOT_DIR/switchguard-cli/target/release/switchguard-cli" "$HOME/.opencode/bin/switchguard-cli"
cp "$ROOT_DIR/switchguard-cli/target/release/switchguard-cli" "$HOME/bin/switchguard-cli"
chmod +x "$HOME/.local/bin/switchguard-cli" "$HOME/.opencode/bin/switchguard-cli" "$HOME/bin/switchguard-cli"


echo "==> [2/3] Resetting workspace/sandbox-app to clean baseline state..."
cd "$ROOT_DIR/workspace/sandbox-app"
git checkout main 2>/dev/null || true
git checkout -- .
git clean -fd

echo "==> [3/3] Verifying baseline pytest suite..."
pytest -q

echo "================================================================="
echo "==> SwitchGuard SRE Sandbox is 100% READY for clean-room demo! <=="
echo "================================================================="
