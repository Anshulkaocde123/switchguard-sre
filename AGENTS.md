# SwitchGuard SRE — Multi-Agent Architecture Context

## Overview
SwitchGuard SRE is a hybrid Rust + Python autonomous incident response pipeline running on Switch Console and Google Antigravity ACP.

## Agent Roster & Directory Isolation
1. **sre-sentinel** (`/workspace/telemetry`)
   - **Addressing:** `Anyone`
   - **Role:** Sanitizes raw production crash logs using the Rust `switchguard-cli scrub` binary, classifies incidents, deduplicates alert storms, initializes the incident state machine, appends records to `incidents_ledger.md`, and dispatches sanitized reproduction parameters to `@sre-repro`. Has zero access to application source code.
2. **sre-repro** (`/workspace/sandbox-app`)
   - **Addressing:** `Me and my agents` (`owner-agents`)
   - **Role:** Writes failing `pytest` reproduction tests first, patches application defects in `cart_service.py`, validates test pass rates, and runs `switchguard-cli verify-diff .` to enforce AST/diff security guardrails. Subject to MAX_ATTEMPTS=2 circuit breaker.
3. **sre-clerk** (`/workspace/release-ops`)
   - **Addressing:** `Me and my agents` (`owner-agents`)
   - **Role:** Human-gated release clerk. Remains idle until the Incident Commander posts `Approved`. Runs `cut_release.py` to package the verified git diff into `releases/`, verifies SHA-256 checksums, rejects empty patches, and logs to `RELEASE_AUDIT.log`.

## Deterministic State Machine (DAG)
All incidents flow through a strict one-way DAG enforced by `workspace/telemetry/incident_state.py`:
```
sre-sentinel → sre-repro → Human Commander → sre-clerk
TRIAGED → REPRODUCING → PATCH_VERIFIED → RELEASED | ESCALATED
```
- **No backward transitions.** Agents cannot re-trigger upstream agents.
- **Circuit Breaker (MAX_ATTEMPTS=2):** If verify-diff or pytest fails twice, the agent halts with `[CIRCUIT_BREAKER_TRIPPED] Escalating to @admin`.
- **Alert-Storm Deduplication:** Duplicate alerts within 5-minute windows are suppressed via content-based fingerprinting (`workspace/telemetry/alert_dedup.py`).

## Security Verification Rules (switchguard-cli v0.3.0)
| Rule | Description |
| :--- | :--- |
| AST-SEC-00 | Empty-patch rejection (exit code 3) |
| AST-SEC-01 | No `eval()` / `exec()` |
| AST-SEC-02 | No `os.system()` |
| AST-SEC-03 | No `subprocess` / `shell=True` |
| AST-SEC-04 | No `__import__()` |
| AST-SEC-05 | No hardcoded secrets |
| AST-SEC-06 | No test tampering / assertion deletion (anti-reward-hacking) |
| AST-SEC-07 | No evasion primitives (`os.popen`, `pty.spawn`, `importlib`, `pickle.loads`, etc.) |
| AST-SEC-08 | No protected path modifications (`.git/`, `.env`, `.sh`) |

## Mandatory Quality & Safety Gates
- All terminal tracebacks posted to Switch rooms must be <= 30 lines and < 1,500 characters to avoid Issue #1226 message splitting.
- Room documents are invisible in bridged Mattermost chat (Issue #1097); always post Markdown tables, pytest tracebacks, and unified git diffs directly in the chat thread.
- Never hardcode `GEMINI_API_KEY`, `GOOGLE_GENAI_API_KEY`, or credentials; load strictly from environment variables.
