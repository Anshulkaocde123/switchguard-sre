#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "==> [1/5] Checking and bootstrapping SwitchGuard Rust AST, Audit & PII Verifier..."
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

echo "==> [2/5] Resetting workspace/sandbox-app to clean baseline state..."
git -C "$ROOT_DIR/workspace/sandbox-app" checkout HEAD -- . 2>/dev/null || true
git -C "$ROOT_DIR/workspace/sandbox-app" clean -fd 2>/dev/null || true
rm -rf "$ROOT_DIR/workspace/sandbox-app/__pycache__" "$ROOT_DIR/workspace/sandbox-app/.pytest_cache"

echo "==> [3/5] Resetting live telemetry state, dedup index, and incidents ledger..."
echo '{"incident_id": "NONE", "current_state": "IDLE", "retry_count": 0}' > "$ROOT_DIR/workspace/telemetry/incident_state.json"
echo '{}' > "$ROOT_DIR/workspace/telemetry/dedup_index.json"
rm -f "$ROOT_DIR/workspace/telemetry/.triage.lock" "$ROOT_DIR/workspace/telemetry/dedup_index.lock" "$ROOT_DIR/workspace/telemetry/incident_state.json.tmp"
rm -rf "$ROOT_DIR/workspace/telemetry/__pycache__"

cat << 'EOF' > "$ROOT_DIR/workspace/telemetry/incidents_ledger.md"
# SwitchGuard SRE — Sanitized Incidents Ledger

| Timestamp | Incident ID | Error Class | Redactions | SHA-256 Digest | Sanitized Summary |
| :--- | :--- | :--- | :--- | :--- | :--- |
| 2026-11-06 05:12:19 UTC | `INC-8041` | `NEGATIVE_TOTAL_CALCULATION` | 2 | `0ee2a4e5bbcf...` | Bearer [REDACTED_AUTH_TOKEN_e806ae] [REDACTED_EMAIL_b4c9a2] FLAT100 -$60.00 cart_service.py line 5 |
EOF

cat << 'EOF' > "$ROOT_DIR/workspace/telemetry/runbook_memory.json"
{
  "version": "1.0",
  "resolutions": [
    {
      "error_classification": "NEGATIVE_TOTAL_CALCULATION",
      "incident_id": "INC-8041",
      "version": "v1.4.2",
      "target_file": "cart_service.py",
      "fix_pattern": "total = max(0.0, subtotal - 100.0)",
      "patch_sha256": "0ee2a4e5bbcf18df31fef0b008755e1c2e9dd0d3843a17e0b3bf67d06a415d28",
      "summary": "Enforce non-negative order total by clamping discount subtotals with max(0.0, ...)",
      "timestamp": "2026-11-06T05:12:19.859440+00:00"
    },
    {
      "error_classification": "ZERO_DIVISION_FAULT",
      "incident_id": "INC-8042",
      "version": "v1.4.3",
      "target_file": "cart_service.py",
      "fix_pattern": "if num_installments <= 0: raise ValueError('num_installments must be positive')",
      "patch_sha256": "98a12f84b64e528198f3ec29a1b89cd123456789abcdef0123456789abcdef01",
      "summary": "Guard against division by zero when calculating installment split",
      "timestamp": "2026-11-06T05:15:00.000000+00:00"
    },
    {
      "error_classification": "CURRENCY_CONVERSION_FAULT",
      "incident_id": "INC-8044",
      "version": "v1.4.4",
      "target_file": "cart_service.py",
      "fix_pattern": "if target_currency not in rates: raise KeyError(f'Unsupported currency: {target_currency}')",
      "patch_sha256": "1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b",
      "summary": "Validate target currency against supported exchange rate matrix",
      "timestamp": "2026-11-06T05:20:00.000000+00:00"
    }
  ]
}
EOF

echo "==> [4/5] Resetting release audit log, purging test artifacts & verifying hash chain..."
cat << 'EOF' > "$ROOT_DIR/workspace/release-ops/RELEASE_AUDIT.log"
# SwitchGuard SRE — Tamper-Evident Hash-Chained Release Audit Ledger
# Genesis Hash: 0000000000000000000000000000000000000000000000000000000000000000
[2026-11-06T05:12:19.859440+00:00] HOTFIX RELEASED: v1.4.2 for INC-8041 | AST_AUDIT=PASS | PATCH=hotfix-INC-8041-v1.4.2.patch | SHA256=0ee2a4e5bbcf18df31fef0b008755e1c2e9dd0d3843a17e0b3bf67d06a415d28 | FILES=1 | LINES_ADDED=1 | PREV_HASH=0000000000000000000000000000000000000000000000000000000000000000 | CHAIN_HASH=77519c5dd1270126469cc783d3e3a8f88f89a38162bcb0f10750af102a46c975
EOF

# Purge synthetic test artifacts and lock files
rm -f "$ROOT_DIR/workspace/release-ops/releases/attestation-INC-9999"* \
      "$ROOT_DIR/workspace/release-ops/releases/hotfix-INC-9999"* \
      "$ROOT_DIR/workspace/release-ops/RELEASE_AUDIT.log.lock"

# Verify audit chain integrity
switchguard-cli verify-audit "$ROOT_DIR/workspace/release-ops/RELEASE_AUDIT.log" >/dev/null

# Regenerate clean executive dashboard
python3 "$ROOT_DIR/workspace/release-ops/cut_release.py" --dashboard >/dev/null

# Restore tracked ledger, audit, and release files to clean committed baseline
git checkout HEAD -- "$ROOT_DIR/workspace/telemetry/incidents_ledger.md" \
                     "$ROOT_DIR/workspace/release-ops/RELEASE_AUDIT.log" \
                     "$ROOT_DIR/workspace/release-ops/releases/" 2>/dev/null || true

echo "==> [5/5] Verifying baseline pytest suite..."
python3 -m pytest -q "$ROOT_DIR/workspace/sandbox-app/test_cart.py"

echo "================================================================="
echo "==> SwitchGuard SRE Sandbox is 100% READY for clean-room demo! <=="
echo "================================================================="
