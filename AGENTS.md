# SwitchGuard SRE — Multi-Agent Architecture Context

## Overview
SwitchGuard SRE is a hybrid Rust + Python autonomous incident response pipeline running on Switch Console and Google Antigravity ACP, hardened for 1,000,000+ alert storms and high concurrency.

## Agent Roster & Directory Isolation
1. **sre-sentinel** (`/workspace/telemetry`)
   - **Addressing:** `Anyone`
   - **Role:** Sanitizes raw production crash logs using the Rust `switchguard-cli scrub` binary, performs O(1) canonical fault fingerprint deduplication (<0.5ms), suppresses alert storms, initializes the incident state machine, appends records to `incidents_ledger.md` with exclusive POSIX locks (`fcntl.flock`), and dispatches sanitized reproduction parameters to `@sre-repro`. Has zero access to application source code.
2. **sre-repro** (`/workspace/sandbox-app`)
   - **Addressing:** `Me and my agents` (`owner-agents`)
   - **Role:** Writes failing `pytest` reproduction tests first, patches application defects in `cart_service.py`, validates test pass rates, and runs `switchguard-cli verify-diff .` to enforce AST/diff security guardrails. Subject to MAX_ATTEMPTS=2 circuit breaker.
3. **sre-clerk** (`/workspace/release-ops`)
   - **Addressing:** `Me and my agents` (`owner-agents`)
   - **Role:** Human-gated release clerk. Remains idle until the Incident Commander posts `Approved`. Runs `cut_release.py` to package verified git diffs into `releases/`, records tamper-evident hash-chained audit trails into `RELEASE_AUDIT.log` with exclusive POSIX locks, verifies SHA-256 checksums, and validates chains via `switchguard-cli verify-audit`.

## High-Concurrency & Durability Architecture
- **O(1) Rust Deduplication:** `switchguard-cli scrub` fingerprints crashes via $\text{SHA256}(\text{error\_class} \parallel \text{file:line})$ against `dedup_index.json` in $<0.5\text{ms}$. Duplicate alerts return `"dedup_status": "SUPPRESSED_DUPLICATE"`, logging spikes without re-waking LLM agents.
- **POSIX Durability (`fcntl.flock` + `os.fsync`):** Concurrent writes to `incidents_ledger.md` and `RELEASE_AUDIT.log` use kernel file locking and fsync guarantees.
- **Tamper-Evident Hash Chaining:** Every hotfix release entry computes $\text{ChainHash}_n = \text{SHA256}(\text{ChainHash}_{n-1} \parallel \text{Timestamp}_n \parallel \text{PatchSHA256}_n)$ from genesis ($0000\dots0000$). Verified by `switchguard-cli verify-audit`.
- **Deterministic State Machine (DAG):** Enforced by `workspace/telemetry/incident_state.py` (`TRIAGED → REPRODUCING → PATCH_VERIFIED → RELEASED | ESCALATED`). No backward transitions; MAX_ATTEMPTS=2 circuit breaker.

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
