# SwitchGuard SRE — Multi-Agent Architecture Context

## Overview
SwitchGuard SRE is a hybrid Rust + Python autonomous incident response pipeline running on Switch Console and Google Antigravity ACP.

## Agent Roster & Directory Isolation
1. **sre-sentinel** (`/workspace/telemetry`)
   - **Addressing:** `Anyone`
   - **Role:** Sanitizes raw production crash logs using the Rust `switchguard-cli scrub` binary, classifies incidents, appends records to `incidents_ledger.md`, and dispatches sanitized reproduction parameters to `@sre-repro`. Has zero access to application source code.
2. **sre-repro** (`/workspace/sandbox-app`)
   - **Addressing:** `Me and my agents` (`owner-agents`)
   - **Role:** Writes failing `pytest` reproduction tests first, patches application defects in `cart_service.py`, validates test pass rates, and runs `switchguard-cli verify-diff .` to enforce AST/diff security guardrails.
3. **sre-clerk** (`/workspace/release-ops`)
   - **Addressing:** `Me and my agents` (`owner-agents`)
   - **Role:** Human-gated release clerk. Remains idle until the Incident Commander posts `Approved`. Runs `cut_release.py` to package the verified git diff into `releases/`, verifies SHA-256 checksums, and logs to `RELEASE_AUDIT.log`.

## Mandatory Quality & Safety Gates
- All terminal tracebacks posted to Switch rooms must be <= 30 lines and < 1,500 characters to avoid Issue #1226 message splitting.
- Room documents are invisible in bridged Mattermost chat (Issue #1097); always post Markdown tables, pytest tracebacks, and unified git diffs directly in the chat thread.
- Never hardcode `GEMINI_API_KEY`, `GOOGLE_GENAI_API_KEY`, or credentials; load strictly from environment variables.
