# SwitchGuard Security & Handoff Protocol

1. **Zero PII Leakage:** Raw logs containing Bearer JWTs, API keys, emails, or IPv4 addresses must be scrubbed via `switchguard-cli scrub` before cross-agent handoff.
2. **Test-First Reproduction:** `sre-repro` must demonstrate a failing `pytest` case prior to modifying application logic. If reproduction is inconclusive, halt and report `STATUS: REPRODUCTION_INCONCLUSIVE`.
3. **Rust AST Diff Gate:** Every code modification in `sandbox-app` must pass `switchguard-cli verify-diff .` with zero forbidden execution primitives (`eval`, `exec`, `os.system`, `os.popen`, `pty.spawn`, `subprocess`, `shell=True`, `__import__`, `importlib`, `compile()`, `pickle.loads`, `shutil.rmtree`, hardcoded credentials). Additionally protected paths (`.git/`, `.env`, `.sh`) are blocked.
4. **Anti-Reward-Hacking (AST-SEC-06):** Diffs that modify test files without touching production source code, or that delete assertion lines, are automatically BLOCKED. Agents must fix the source, not weaken the tests.
5. **Empty-Patch Rejection (AST-SEC-00):** Both `switchguard-cli verify-diff` and `cut_release.py` reject empty diffs (0-byte patches) with `EMPTY_PATCH_REJECTED` (exit code 3). The diff always uses `git diff HEAD` to capture staged + unstaged changes.
6. **Human-in-the-Loop Release:** `sre-clerk` cannot execute `cut_release.py` without an explicit `Approved` message from the human Incident Commander.
7. **Deterministic State Machine (Edge Case D):** All incidents flow through a strict one-way DAG: `sre-sentinel → sre-repro → Human Commander → sre-clerk`. State is tracked in `workspace/telemetry/incident_state.json` with states: `TRIAGED → REPRODUCING → PATCH_VERIFIED → RELEASED | ESCALATED`.
8. **Circuit Breaker (MAX_ATTEMPTS=2):** If `verify-diff` or `pytest` fails twice for the same incident, the agent halts and outputs `[CIRCUIT_BREAKER_TRIPPED] Escalating to @admin`. No infinite loops.
9. **Alert-Storm Deduplication:** Duplicate alerts with the same content fingerprint within a 5-minute window are suppressed. Only the first occurrence creates an incident.
10. **Issue #1158 & #1226 Platform Defenses:** Keep `kickoff:` in templates to a single plain-text line; all chat tracebacks capped at 30 lines / 1,500 characters.
