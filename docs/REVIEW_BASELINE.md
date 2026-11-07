# SwitchGuard SRE — Baseline Audit & Claim Inventory

**Date:** 2026-11-08  
**Branch:** `hardening/review-fixes`  
**Git Commit / Baseline State:** Baseline inspection before behavioral modifications  
**Environment:** Linux x86_64, Rust 1.99.1, Python 3.12.3

---

## 1. Baseline Test Suite Execution Summary

The baseline verification suite was executed using:
```bash
cargo build --release --manifest-path switchguard-cli/Cargo.toml
python3 scripts/mega_sre_test_suite.py
```

### Results
- **Overall Verdict:** 30 / 30 Passed (100%)
- **Total Suite Execution Time:** ~2281.9 ms (2.28 s)
- **Breakdown by Suite:**
  1. `SUITE 1: Smoke & Environment Integrity`: 3/3 PASS (31.4 ms)
  2. `SUITE 2: Exhaustive Unit Tests (pytest + Scrubber)`: 3/3 PASS (169.5 ms)
  3. `SUITE 3: Adversarial Fuzzing, Syntax Errors & AST Bypass`: 11/11 PASS (483.6 ms)
  4. `SUITE 4: High-Concurrency Alert Storm Stress Test (32 Workers)`: 1/1 PASS (597.0 ms)
  5. `SUITE 5: End-to-End Integration, Hash-Chain Tamper Detection & Rollback`: 6/6 PASS (482.8 ms)
  6. `SUITE 6: Agent Loop Prevention & Circuit Breaker Logic`: 5/5 PASS (16.7 ms)
  7. `SUITE 7: Latency & Performance Benchmarks (20 Iterations)`: 1/1 PASS (500.3 ms)
- **Pytest Sandbox Unit Tests:** 28 passed in 0.04s (`pytest workspace/sandbox-app -v`)
- **Security Chaos Test:** 5/5 PASS (`python3 scripts/security_chaos_test.py`)

---

## 2. Comprehensive Inventory of Claims & Adjectives

Below is the exhaustive inventory of all quantitative claims, strong adjectives, badges, and architectural claims across `README.md`, `BLOG.md`, `HACKATHON_SUBMISSION.md`, `docs/index.html`, `docs/blog.html`, and related assets.

| # | Claim / Adjective / Phrase | Location(s) Found | Stated Value / Context | Current Evidence (Code/Command) | Verdict | Technical Finding & Hardening Action Required |
|---|---|---|---|---|---|---|
| 1 | **"Tests-30/30 Passing"** / "30 deterministic assertions" | README.md badges & §8, BLOG.md badges & §7, HACKATHON_SUBMISSION.md, docs/index.html | 30/30 tests passing in mega suite | `python3 scripts/mega_sre_test_suite.py` passes all 30 checks. | **SUPPORTED** | Suite passes, but count must be kept dynamically honest when new tests are added in subsequent phases. |
| 2 | **"PRODUCTION READY"** / "100% PASSED — PRODUCTION READY" | README.md §8, BLOG.md §7, TEST_VERIFICATION_REPORT.md, mega_sre_test_suite.py | Claims system is production ready | The project is a hackathon prototype targeting a single toy Python microservice (`cart_service.py`), with no authentication, single-language support, denylist-only AST checks, and no real deployment infra. | **UNSUPPORTED** | Must downgrade tone across all documentation to "hardened prototype" or "reproducible verification benchmark". |
| 3 | **"TEE-ready"** / **"TEE AUDIT ACTIVE"** / "designed for AWS Nitro Enclaves / Confidential VMs" | README.md Diagram 1, Diagram 4, §7; BLOG.md §2, Diagram 4; HACKATHON_SUBMISSION.md Block 1, 4; docs/index.html line 559 | Claims TEE audit active / TEE-ready manifests | No hardware enclave integration, no SGX/Nitro attestation quotes, no measurement registers. Merely generates a JSON receipt with a static hardcoded salt (`"switchguard-tee-default-salt-v1"`). | **UNSUPPORTED** | Relabel to "designed to be bound to a TEE attestation; not implemented". Remove "TEE AUDIT ACTIVE" from dashboard. |
| 4 | **"Cryptographic"** / "Tamper-evident release audit ledger" / "Cryptographic Proof-of-Hotfix Ledger" | Makefile, README.md §2, Diagram 4; BLOG.md §2, §3; HACKATHON_SUBMISSION.md Block 1 | Claims release audit log is cryptographically tamper-evident from genesis | `cut_release.py` and `switchguard-cli` compute plain unkeyed SHA-256 (`SHA256(prev_hash \|\| ts \|\| patch_sha)`). Anyone with write access to `RELEASE_AUDIT.log` can recompute the entire chain from scratch. | **PARTIAL** | Plain hash chain is not tamper-evident against local file writers. Must convert to keyed HMAC-SHA256 with key outside agent scope (Phase 3). |
| 5 | **"O(1)" deduplication** | README.md §2, Diagram 1; BLOG.md §2, Figure 1; HACKATHON_SUBMISSION.md Block 1, 2, 5; docs/index.html line 592, 597 | Canonical fault fingerprinting deduplication in $O(1)$ | `switchguard-cli/src/main.rs` lines 205-240 loads `dedup_index.json` into memory via `serde_json`. While hash map lookup is $O(1)$, file I/O deserializes and writes the entire JSON file ($O(N)$). | **PARTIAL** | Qualify claim precisely: in-memory fingerprint lookup is $O(1)$ hash table lookup, but disk persistence is bounded file I/O. |
| 6 | **"<0.5ms"** / "under 0.5ms" scrub / dedup | README.md §2, Diagram 1; BLOG.md §2, Figure 1; HACKATHON_SUBMISSION.md Block 1, 2, 5 | Scrubbing and dedup under 0.5ms | Measured end-to-end CLI execution (`switchguard-cli scrub`) takes ~9.5–11.1ms. Core in-memory regex may be <0.5ms, but end-to-end CLI includes process spawn, JSON deserialization, and file locking. | **PARTIAL** | Instrument Rust binary with `--timing` to isolate core internal elapsed time vs end-to-end process invocation (Phase 5). |
| 7 | **Diff Latency Discrepancies** ("8.11ms" vs "8.28ms" vs "9.07ms") | README.md badge (`9.07ms`), §7 (`8.11ms`), §8 (`8.11ms`); BLOG.md badge (`8.28ms`), §2 (`9.07ms`), §6 (`8.11ms`); HACKATHON_SUBMISSION.md (`9.07ms`) | p50 latency of `switchguard-cli verify-diff` | Hardcoded values across README, BLOG, badges, and dashboard contradict each other. Baseline run measured p50 = 9.07ms - 9.95ms. | **PARTIAL / DISCREPANT** | Generate all numbers from an actual benchmark run (`scripts/benchmark.py`) and replace hardcoded discrepancies (Phase 5). |
| 8 | **"10 rules"** (AST-SEC-00 to AST-SEC-09) | README.md §2, §5; BLOG.md §2, §4; HACKATHON_SUBMISSION.md; switchguard-cli | 10 AST and git security rules enforced | `switchguard-cli/src/main.rs` implements AST-SEC-00 through 09. All 10 exist and pass tests. | **SUPPORTED** | Rules are currently a denylist with blind spots (network, ctypes, pickle, filesystem writes, introspection). Must be expanded in Phase 1. |
| 9 | **"Rust AST gate"** / "compiled Rust binary ... walks Python's native AST" | README.md title & §2; BLOG.md title & §2; HACKATHON_SUBMISSION.md Block 1, 4 | Implies the Rust binary itself contains a Python AST parser | `switchguard-cli/src/main.rs` lines 514–673 embeds a Python script `AST_INSPECTOR_SCRIPT` and invokes `python3 -c` via `std::process::Command`. Rust does diff scanning and orchestration, while Python parses its own AST. | **PARTIAL** | Reword honestly: "compiled Rust verifier combining diff scanning with Python AST analysis" (Phase 2). |
| 10 | **"permanently merged into upstream core"** (Switch PR #1566 and PR #1659) | README.md §9, BLOG.md §8 | Claims PR #1566 and PR #1659 are merged into `sandbox-quantum/switch` | Checked via GitHub API (`curl https://api.github.com/repos/sandbox-quantum/switch/pulls/1566`): PR #1566 is `"state": "open"`, `"merged": false`. PR #1659 is `"state": "open"`, `"merged": false`. Issues #827 and #837 are also open. | **UNSUPPORTED / FALSE** | Must be reworded from "permanently merged" to "submitted and pending upstream review" (Phase 7). |
| 11 | **"Compiled machine code outside Python memory cannot be modified by the LLM"** | README.md §7 Trade-off 1; BLOG.md §6 Trade-off 1 | Claims LLM agent cannot tamper with the verifier | In standard execution, the agent process runs as the same OS user (`anshul-jain`) and owns `$HOME/.local/bin/switchguard-cli` with write permissions. If an agent has arbitrary shell access, it can overwrite the binary. | **PARTIAL** | State filesystem permissions assumption explicitly. Add startup sanity check to verify binary and its directory are read-only or match pinned SHA-256 (Phase 2). |
| 12 | **"Zero external package dependencies"** | README.md §7 Trade-off 3; BLOG.md §6 Trade-off 3 | Claims verifier has zero external package dependencies | Python verifier script has zero external packages (uses stdlib `ast`, `os`, `sys`, `json`). Rust CLI relies on 4 external crates (`regex`, `serde`, `serde_json`, `sha2`). | **PARTIAL** | Clarify scope: zero external Python packages; Rust CLI uses standard audited crates (`sha2`, `serde`, `regex`). |
| 13 | **"32 Workers Concurrency"** / "96.8% token savings" | README.md badge & §4; BLOG.md badge & §2; Makefile | 32 parallel alert workers handled without race conditions; 96.8% token savings | `mega_sre_test_suite.py` Suite 4 launches 32 threads against dedup lock: 1 `FIRST_SEEN`, 31 `SUPPRESSED_DUPLICATE`. 31/32 = 96.875% suppression. | **SUPPORTED** | Verified in Suite 4. |
| 14 | **"Zero-RAM static dashboard"** / "0 MB background server RAM" | README.md §1, §7; docs/index.html | Observability dashboard uses 0 MB background RAM | `docs/index.html` is a static client-side single-page app requiring no active backend server. | **SUPPORTED** | Verified static HTML/JS architecture. |
| 15 | **"MIT License"** | README.md §11, BLOG.md §10 | Claims project is licensed under MIT | No `LICENSE` file exists in the repository root. | **UNSUPPORTED** | Add missing `LICENSE` file in Phase 8. |
| 16 | **"Salted HMAC Tokens ([REDACTED_EMAIL_a1b2c3])"** | README.md §2; BLOG.md §2; switchguard-cli | Claims redaction tokens are computed via HMAC | `main.rs` lines 143-152 computes `Sha256(salt + ":" + val)[..6]`. This is a truncated prefix-keyed SHA-256 hash, not an RFC 2104 HMAC. | **PARTIAL** | Clarify as salted cryptographic prefix-hash or upgrade to true HMAC-SHA256. |
| 17 | **"Deterministic traceback compaction (<= 30 lines and < 1,500 characters)"** | README.md §9; BLOG.md §8; AGENTS.md | Traceback limits enforced to avoid ACP channel splitting | Stated in agent prompt guidelines (`AGENTS.md`), but not enforced by the binary gate. | **PARTIAL** | Clarify that this is a prompt/protocol guideline rather than an OS-level gate. |
| 18 | **"2-Strike Circuit Breaker (MAX_ATTEMPTS = 2)"** | README.md §7; BLOG.md §6; incident_state.py | Incident halts after 2 failed attempts | Enforced in `workspace/telemetry/incident_state.py` and validated by Suite 6. | **SUPPORTED** | Verified in Suite 6. |

---

## 3. Summary of Baseline Audit Findings

1. **Gate Architecture Reality:** The gate is an orchestration hybrid: a compiled Rust binary orchestrating diff extraction, line parsing, git tree inspection, deduplication, and HMAC/SHA-256 verification, which invokes Python's standard library `ast.parse` and `ast.walk` to inspect Python syntax. It is not an in-process Rust Python parser.
2. **Denylist Vulnerability:** AST-SEC-00 through 09 only block a narrow denylist. An injected patch can still import network libraries (`urllib`, `requests`, `httpx`), native unsafe loaders (`ctypes`, `pickle`), sandbox escape via introspection (`__class__.__subclasses__`, `globals()`), write to disk outside the sandbox, or use base64-encoded calls.
3. **Audit Log Vulnerability:** The audit chain is plain SHA-256 with no secret key. Any process with write access can overwrite the log and recalculate the chain.
4. **Scrubber vs Injection Boundary:** The scrubber redacts secrets but does not sanitize prompt injection instructions. Untrusted log data must be separated into an envelope and flagged for injection heuristics.
5. **Upstream PR Status:** Both Switch PR #1566 and PR #1659 are **open** (not merged). Documentation claiming "permanently merged" is factually incorrect and must be corrected to "submitted".
6. **Discrepant Performance Figures:** Multiple numbers in README, BLOG, and badges conflict (9.07ms vs 8.11ms vs 8.28ms). A unified benchmark script must establish reproducible ground truth.
7. **Repository Hygiene:** Missing `LICENSE` file; internal planning documents (`Switch Hackathon Winning Blueprint.pdf`, etc.) reside in root.
