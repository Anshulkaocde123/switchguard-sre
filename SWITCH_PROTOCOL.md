# SwitchGuard Security & Handoff Protocol

1. **Zero PII Leakage:** Raw logs containing Bearer JWTs, API keys, emails, or IPv4 addresses must be scrubbed via `switchguard-cli scrub` before cross-agent handoff.
2. **O(1) Rust Alert-Storm Deduplication:** `switchguard-cli scrub` computes a canonical fault fingerprint $\text{SHA256}(\text{error\_classification} \parallel \text{normalized\_file\_line})$ and checks a lock-protected state index (`dedup_index.json`). Duplicate alerts within active windows are suppressed in $< 0.5\text{ms}$ with `"dedup_status": "SUPPRESSED_DUPLICATE"`, logging spikes without dispatching `@sre-repro`.
3. **POSIX File Locking & Durability:** All concurrent writes to `incidents_ledger.md` and `RELEASE_AUDIT.log` use exclusive POSIX file locks (`fcntl.flock(f, fcntl.LOCK_EX)`) paired with `os.fsync()` to eliminate corruption under 50,000+ alerts/minute storms.
4. **Tamper-Evident Hash-Chained Audit Ledger:** Every entry in `RELEASE_AUDIT.log` computes:
   $$\text{ChainHash}_n = \text{SHA256}(\text{ChainHash}_{n-1} \parallel \text{Timestamp}_n \parallel \text{PatchSHA256}_n)$$
   anchored to genesis hash $0000\dots0000$. Verified by `switchguard-cli verify-audit`.
5. **Test-First Reproduction:** `sre-repro` must demonstrate a failing `pytest` case prior to modifying application logic. If reproduction is inconclusive, halt and report `STATUS: REPRODUCTION_INCONCLUSIVE`.
6. **Rust AST Diff Gate:** Every code modification in `sandbox-app` must pass `switchguard-cli verify-diff .` with zero forbidden execution primitives (`eval`, `exec`, `os.system`, `os.popen`, `pty.spawn`, `subprocess`, `shell=True`, `__import__`, `importlib`, `compile()`, `pickle.loads`, `shutil.rmtree`, hardcoded credentials). Additionally protected paths (`.git/`, `.env`, `.sh`) are blocked.
7. **Anti-Reward-Hacking (AST-SEC-06):** Diffs that modify test files without touching production source code, or that delete assertion lines, are automatically BLOCKED. Agents must fix the source, not weaken the tests.
8. **Empty-Patch Rejection (AST-SEC-00):** Both `switchguard-cli verify-diff` and `cut_release.py` reject empty diffs (0-byte patches) with `EMPTY_PATCH_REJECTED` (exit code 3). Diffs always compare against `git diff HEAD` to capture staged + unstaged changes.
9. **Human-in-the-Loop Release:** `sre-clerk` cannot execute `cut_release.py` without an explicit `Approved` message from the human Incident Commander.
10. **Deterministic State Machine & Circuit Breaker:** All incidents flow through a strict one-way DAG: `sre-sentinel → sre-repro → Human Commander → sre-clerk`. State is tracked in `workspace/telemetry/incident_state.json`. If `verify-diff` or `pytest` fails twice, the agent halts with `[CIRCUIT_BREAKER_TRIPPED] Escalating to @admin`.
11. **Platform Defenses & Upstream Switch PRs:**
    - **Upstream Switch PR #827 (Issue #1097):** Room documents are invisible in bridged Mattermost chat; all status scorecards, Markdown tables, pytest outputs, and unified git diffs are posted directly into the chat thread.
    - **Upstream Switch PR #837 (Issue #1226):** All terminal tracebacks posted to Switch rooms must be <= 30 lines and < 1,500 characters to prevent ACP message splitting.
    - **Issue #1158:** Keep `kickoff:` in templates to a single plain-text line without multiline block scalars.
