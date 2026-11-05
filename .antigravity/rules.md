# SwitchGuard Antigravity Rules

## 1. Directory Isolation
- Agents must operate strictly within their assigned working directory:
  - `sre-sentinel` -> `/workspace/telemetry`
  - `sre-repro` -> `/workspace/sandbox-app`
  - `sre-clerk` -> `/workspace/release-ops`

## 2. Security Verification (switchguard-cli v0.3.0)
- Automatically run `switchguard-cli verify-diff workspace/sandbox-app` on any changes to `cart_service.py`.
- Never commit hardcoded API keys, JWTs, or secrets.
- Empty patches (0-byte diffs) are rejected with exit code 3 (EMPTY_PATCH_REJECTED).
- Diffs that delete test assertions or modify only test files are BLOCKED (AST-SEC-06 anti-reward-hacking).
- Evasion primitives (`os.popen`, `pty.spawn`, `importlib`, `pickle.loads`, etc.) are BLOCKED (AST-SEC-07).
- Protected paths (`.git/`, `.env`, `.sh`) cannot be touched in diffs (AST-SEC-08).

## 3. High-Concurrency & Durability
- O(1) canonical fault fingerprint deduplication (<0.5ms) suppresses duplicate alert storms in Rust.
- POSIX file locking (`fcntl.flock(f, fcntl.LOCK_EX)`) and `os.fsync()` must guard all ledger and audit log writes.
- Cryptographic hash chaining in `RELEASE_AUDIT.log` anchored to genesis hash $0000\dots0000$.
- Verify audit log integrity using `switchguard-cli verify-audit`.

## 4. Communication Limits (Issue #1226 & #1097)
- Terminal tracebacks posted to rooms must be <= 30 lines and < 1,500 characters.
- Render all scorecards, diffs, and test results as direct Markdown in chat.

## 5. State Machine & Circuit Breaker
- All incidents must flow through the deterministic DAG: TRIAGED → REPRODUCING → PATCH_VERIFIED → RELEASED | ESCALATED.
- No backward transitions. No agent-to-agent ping-pong.
- MAX_ATTEMPTS=2: if verify-diff or pytest fails twice, halt with `[CIRCUIT_BREAKER_TRIPPED]`.
