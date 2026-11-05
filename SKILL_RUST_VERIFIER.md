# SwitchGuard Rust Security & AST Verifier Skill Specification

## Binary Overview
`switchguard-cli` is a compiled Rust CLI providing sub-millisecond log sanitization and deterministic AST diff gating for autonomous SRE agents.

## Subcommand: `scrub`
Redacts Bearer JWTs, secret keys, emails, and IPv4 addresses from raw alerts before cross-agent handoff.

### Usage
```bash
switchguard-cli scrub "<raw_log_payload_or_path>"
```

### JSON Response Schema
```json
{
  "status": "SANITIZED",
  "sanitized_text": "...",
  "clean_payload": "...",
  "sha256": "<64_char_hex_hash>",
  "error_classification": "NEGATIVE_TOTAL_CALCULATION",
  "redacted_count": 2
}
```

## Subcommand: `verify-diff`
Inspects git diff in the target directory, checks for forbidden dynamic execution primitives, and enforces safety rules.

### Usage
```bash
switchguard-cli verify-diff <target_workspace_path>
```

### Exit Codes
- `0`: Diff passed all security guardrails (`verdict: "PASS"`).
- `2`: Forbidden primitives detected (`verdict: "BLOCKED"`).

### Enforced Rule IDs
0. `AST-SEC-00: NO_EMPTY_PATCH`: Rejects empty diffs or patches without application code changes (exit 3).
1. `AST-SEC-01: NO_EVAL_EXEC`: Rejects `eval()` and `exec()`.
2. `AST-SEC-02: NO_OS_SYSTEM`: Rejects `os.system()` calls.
3. `AST-SEC-03: NO_SUBPROCESS`: Rejects `subprocess` and `shell=True`.
4. `AST-SEC-04: NO_DYNAMIC_IMPORT`: Rejects `__import__()` and `importlib`.
5. `AST-SEC-05: NO_HARDCODED_SECRETS`: Rejects `sk_live_`, `AIzaSy`, `ghp_` tokens.
6. `AST-SEC-06: NO_TEST_TAMPERING`: Rejects deletion of tests or assertions in test suites.
7. `AST-SEC-07: NO_GIT_OR_ENV_TAMPERING`: Rejects modifications to `.git/`, `.env`, or `*.sh`.
8. `AST-SEC-08: NO_OBFUSCATED_EXEC`: Rejects dynamic evasions (`getattr()`, `builtins`, `os.popen`, `pty.spawn`, `socket`).
9. `AST-SEC-09: MINIMAL_BLAST_RADIUS`: Rejects hotfixes with $>25$ added lines in production `.py` files.
