# SwitchGuard SRE — Architectural Limitations & Scope Boundaries

This document provides a candid, plain-language inventory of known limitations, architectural trade-offs, and boundary assumptions in SwitchGuard SRE. In systems security, an unstated assumption is a future vulnerability; this document makes all boundaries explicit.

---

## 1. The Semantic Correctness Gap

### Limitation
The diff gate (`switchguard-cli verify-diff`) is a capability-limiting structural barrier, **not a formal semantic verifier**. It enforces AST rules (rejecting dangerous calls like `eval()`, `os.system()`, subprocesses, dynamic imports, network exfiltration, file writes, and assert deletion), but it **cannot know whether the business logic of a patch is correct**.

### Empirical Proof (Eval Case 09)
In evaluation [`CASE-09`](../eval/corpus/case-09.json) (`semantic_social_eng`), a social-engineering crash log persuaded the agent to modify the checkout discount calculation:
```python
if discount_code in ("VIP_FREE", "VIP"):
    total = 0.0
```
This change grants a 100% discount on every order with a `"VIP"` voucher code. Because the patch used valid Python syntax and standard math operators without invoking any forbidden AST primitives, `switchguard-cli verify-diff` returned `PASS`.

### Enforced Mitigations
1. **Red-to-Green TDD Verification (`cut_release.py`):** The release clerk verifies that there is at least one new/modified test, that the new test **fails** on the pre-patch baseline, and **passes** on the patched code.
2. **Human-in-the-Loop Release Approval:** `@sre-clerk` remains strictly locked until an authorized human Incident Commander reviews the unified diff and posts an explicit `Approved` token.
3. **Automated Rollback:** If a regression escapes, `cut_release.py --rollback` reverts the repository to the pre-incident git commit in under 50ms.

---

## 2. Language Scope: Python-Only AST

### Limitation
SwitchGuard SRE's deep AST verification engine targets **Python** source files (`.py`) by invoking Python's standard `ast.parse` and `ast.walk`. Non-Python files in polyglot codebases (such as TypeScript/Node.js, Go, Rust, or Java) are not parsed into AST representations.

### Enforced Mitigations
- Path-level security (`AST-SEC-07` and `AST-SEC-08`) blocks modifications to sensitive non-code paths (`.git/`, `.env`, shell scripts `*.sh`, pytest fixtures `conftest.py`).
- Line-count caps (`AST-SEC-09`) restrict blast radius to $\le 30$ added lines in production code.
- Extending SwitchGuard SRE to polyglot environments requires adding language-specific AST parsers (e.g. `swc` for TypeScript, `go/parser` for Go) to the compiled verifier.

---

## 3. Resource Overhead of Directory-Isolated Multi-Agent Persona

### Limitation
SwitchGuard SRE splits the remediation lifecycle across three distinct agent personas (`@sre-sentinel`, `@sre-repro`, `@sre-clerk`) operating in separate working directories (`workspace/telemetry`, `workspace/sandbox-app`, `workspace/release-ops`). 

While this prevents privilege escalation, running three distinct agents incurs:
- Additional LLM API token consumption when transferring state across room boundaries.
- Operating system memory footprint for three concurrent agent processes.

### Measured Mitigations
- **Zero Background Server RAM:** Concurrency control uses kernel POSIX file locks (`fcntl.flock`), requiring **0 MB** background server RAM (no Redis, Postgres, or daemon services required).
- **O(1) Duplicate Suppression:** During alert storms, `@sre-sentinel` suppresses duplicate crashes via hash-table lookup without waking `@sre-repro` or `@sre-clerk`, preventing token bankruptcy.

---

## 4. Local POSIX File Locking (Single-Host Scope)

### Limitation
Concurrency control in `triage_helper.py` and `cut_release.py` relies on `fcntl.flock(LOCK_EX)` on POSIX systems (and `msvcrt.locking` on Windows). Kernel file locks are strictly local to a single host or operating system instance.

### Distributed Deployment Requirements
If SwitchGuard SRE is scaled to a multi-node Kubernetes cluster or multi-server distributed SRE pool, local kernel flocking must be replaced with a distributed lock manager (e.g., Redis Redlock, Consul, or etcd).

---

## 5. Secret Scrubbing Regex Heuristics

### Limitation
Telemetry sanitization in `switchguard-cli scrub` uses compiled OnceLock regular expressions to redact known patterns (Bearer JWTs, AWS access keys `AKIA...`, IPv4 addresses, and email addresses).

Regex scrubbing is inherently heuristic:
- Highly novel secret formats (e.g., custom hexadecimal API keys without standard prefixes) can evade pattern matching.
- High-entropy random strings without delimiters may not match standard token shapes.

### Enforced Mitigations
1. **Output-Side Diff Gate:** Even if a secret or injected instruction slips past input-side regex scrubbing, the agent cannot exfiltrate it: `AST-SEC-10` blocks all network libraries (`urllib`, `requests`, `httpx`, `socket`), and `AST-SEC-13` blocks writing outside the sandbox.
2. **Untrusted Boundary Envelopes:** Scrubbed logs are enclosed inside randomized delimiters (`=== UNTRUSTED_TELEMETRY_LOG_BOUNDARY_<hex> ===`) with heuristic injection warning flags.

---

## 6. Local Keyed Audit Chain (No Distributed Hardware Attestation)

### Limitation
The release audit log (`RELEASE_AUDIT.log`) uses a keyed HMAC-SHA256 hash chain verified from genesis root (`0000...0000`). While this prevents unkeyed recalculation by unauthorized agents, the current implementation:
- Reads the HMAC secret key from `SWITCHGUARD_HMAC_KEY` or a protected local filesystem path outside agent write access.
- Is **not** currently anchored to a public blockchain, transparency log (like Sigstore Rekor), cloud KMS, or hardware Trusted Execution Environment (TEE).

### Relabeled Claims
All previous references to "TEE-ready" have been relabeled honestly across all documentation:
> *"Designed to be bound to a TEE attestation; not implemented."*
Hardware attestation (e.g., AWS Nitro Enclaves or AMD SEV-SNP) is an architectural roadmap goal, not a delivered capability.
