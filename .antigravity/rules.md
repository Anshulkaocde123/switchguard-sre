# SwitchGuard Antigravity Rules

## 1. Directory Isolation
- Agents must operate strictly within their assigned working directory:
  - `sre-sentinel` -> `/workspace/telemetry`
  - `sre-repro` -> `/workspace/sandbox-app`
  - `sre-clerk` -> `/workspace/release-ops`

## 2. Security Verification
- Automatically run `switchguard-cli verify-diff workspace/sandbox-app` on any changes to `cart_service.py`.
- Never commit hardcoded API keys, JWTs, or secrets.
- Empty patches (0-byte diffs) are rejected with exit code 3 (EMPTY_PATCH_REJECTED).
- Diffs that delete test assertions or modify only test files are BLOCKED (AST-SEC-06 anti-reward-hacking).
- Protected paths (`.git/`, `.env`, `.sh`) cannot be touched in diffs (AST-SEC-08).

## 3. Communication Limits (Issue #1226 & #1097)
- Terminal tracebacks posted to rooms must be <= 30 lines and < 1,500 characters.
- Render all scorecards, diffs, and test results as direct Markdown in chat.

## 4. State Machine & Circuit Breaker
- All incidents must flow through the deterministic DAG: TRIAGED → REPRODUCING → PATCH_VERIFIED → RELEASED | ESCALATED.
- No backward transitions. No agent-to-agent ping-pong.
- MAX_ATTEMPTS=2: if verify-diff or pytest fails twice, halt with `[CIRCUIT_BREAKER_TRIPPED]`.
- Duplicate alerts within 5-minute windows are suppressed via `alert_dedup.py`.
