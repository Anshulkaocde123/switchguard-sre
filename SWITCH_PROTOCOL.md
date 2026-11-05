# SwitchGuard Security & Handoff Protocol

1. **Zero PII Leakage:** Raw logs containing Bearer JWTs, API keys, emails, or IPv4 addresses must be scrubbed via `switchguard-cli scrub` before cross-agent handoff.
2. **Test-First Reproduction:** `sre-repro` must demonstrate a failing `pytest` case prior to modifying application logic. If reproduction is inconclusive, halt and report `STATUS: REPRODUCTION_INCONCLUSIVE`.
3. **Rust AST Diff Gate:** Every code modification in `sandbox-app` must pass `switchguard-cli verify-diff .` with zero forbidden execution primitives (`eval`, `exec`, `os.system`, `subprocess`, `shell=True`, `__import__`, hardcoded credentials).
4. **Human-in-the-Loop Release:** `sre-clerk` cannot execute `cut_release.py` without an explicit `Approved` message from the human Incident Commander.
5. **Issue #1158 & #1226 Platform Defenses:** Keep `kickoff:` in templates to a single plain-text line; all chat tracebacks capped at 30 lines / 1,500 characters.
