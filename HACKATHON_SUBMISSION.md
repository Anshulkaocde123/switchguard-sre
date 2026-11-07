# SwitchGuard SRE — Official Hackathon Submission Package
**Flip the Switch Hackathon (2026)**  
**Submission Repository:** `https://github.com/Anshulkaocde123/switchguard-sre`  
**Official 1:57 Demo Video:** `https://youtu.be/a3mLn3PMPjo`  
**Live Control Plane:** `https://anshulkaocde123.github.io/switchguard-sre/`  
**Interactive Technical Blog:** `https://anshulkaocde123.github.io/switchguard-sre/blog.html`  
**Technical Architecture Guide:** `https://github.com/Anshulkaocde123/switchguard-sre/blob/main/BLOG.md`

---

## Block 1: Project Pitch / Description

```text
Giving autonomous SRE agents unconstrained shell access fails in production: raw crash traces leak customer secrets (JWTs, payment PANs, AWS keys) to external cloud LLM APIs, adversarial prompt injection inside telemetry headers coerces agents into executing arbitrary shell commands (curl | sh), and high-volume alert storms cause token bankruptcy and state-file race conditions.

SwitchGuard SRE is an autonomous incident response and patch verification pipeline built on Switch Console and Google Antigravity ACP. Instead of relying on fragile prompt instructions, it isolates three role-scoped agents inside separate directories and gates every action at the operating-system boundary through a compiled Rust binary (switchguard-cli):

1. Telemetry Intake (@sre-sentinel): Scrubs raw crash dumps into salted HMAC correlation tokens in 8.92ms core (10.96ms end-to-end), preserves release version strings (v1.4.2.0) against IPv4 regex collisions, and enforces O(1) hash-table fault fingerprint deduplication under a POSIX fcntl.flock file mutex—suppressing 32-worker alert storms with zero duplicate LLM calls or JSON corruption.
2. Sandbox Reproduction (@sre-repro): Enforces strict Test-Driven Development (writing the failing pytest reproduction test first in test_cart.py before patching cart_service.py), bounded by a 2-strike circuit breaker (MAX_ATTEMPTS=2). Before requesting release, it runs switchguard-cli verify-diff, which combines unified git diff parsing with Python Abstract Syntax Tree analysis (ast.walk) in 49.53ms core (51.47ms end-to-end) p50 to enforce 16 security rules—blocking eval/exec, multiline os.system splits, subprocess calls, untracked conftest.py backdoors, network exfiltration, and reward-hacking assert deletions.
3. Cryptographic Release (@sre-clerk): Remains locked until a human Incident Commander posts explicit approval in-thread. It verifies 5 pre-release gates, exports the unified git patch, generates an attestation manifest binding binary and patch SHA-256 digests (designed to be bound to a TEE attestation; not implemented), and appends a keyed HMAC-SHA256 entry to RELEASE_AUDIT.log verified from genesis.
4. Upstream Switch Core Contributions: Contributed two service connectors to sandbox-quantum/switch—Supabase Remote MCP Connector (PR #1566, closes Issue #827) and Trello Remote MCP Connector (PR #1659, closes Issue #837).
```

---

## Block 2: How did you use Switch in your project?

```text
I used Switch Console (v0.41.0 Canary) and Google Antigravity ACP to run a 3-agent, directory-isolated SRE war room inside the #sre-war-room channel, bridged with Switch's local Mattermost integration:

1. Directory-Isolated Agent Roles & OS-Boundary Enforcement:
- @sre-sentinel (/workspace/telemetry | ACL: Anyone): Intake and sanitization agent. Subscribes to incoming crash alerts, runs our compiled Rust binary (switchguard-cli scrub) to replace secrets with salted HMAC tokens, checks runbook_memory.json for prior fix patterns, and updates dedup_index.json under a POSIX fcntl.flock lock. It has zero read or write access to application source code.
- @sre-repro (/workspace/sandbox-app | ACL: Owner & Agents): Reproduction and patching engineer. Wakes on sanitized triage handoffs, writes a failing reproduction test in test_cart.py, applies a minimal fix (<30 lines) in cart_service.py, and executes switchguard-cli verify-diff . to validate all 10 AST and syntax gates. A deterministic 2-strike circuit breaker (MAX_ATTEMPTS=2) halts execution into CIRCUIT_BROKEN if two patch attempts fail verification.
- @sre-clerk (/workspace/release-ops | ACL: Human Approval Gate): Release authority. Remains idle until the human Incident Commander posts '@sre-clerk Approved. Cut hotfix release v1.4.2 for INC-8041.' It validates 5 pre-release checks, packages the hotfix patch, writes a JSON receipt (designed to be bound to a TEE attestation; not implemented), and links a keyed HMAC-SHA256 record into RELEASE_AUDIT.log.

2. Human-in-the-Loop Operational Governance:
Operators watch sanitized triage reports, reproduction test failures, and unified diffs stream live inside #sre-war-room. Agents handle log scrubbing, root-cause isolation, and TDD patching at machine speed, while the human commander retains final release and 1-command rollback authority.
```

---

## Block 3: What did you like about Switch, and what would you improve?

```text
What Worked Well:
1. Native ACP Multi-Agent Routing: Switch's room dispatch model and @-mention handoffs let @sre-sentinel, @sre-repro, and @sre-clerk pass structured incident state asynchronously without fragile webhook glue.
2. Per-Agent Working Directory Isolation: Binding distinct working directories in switchguard-sre.template.yaml gave us clean filesystem boundaries between untrusted telemetry (/workspace/telemetry), application code (/workspace/sandbox-app), and release keys (/workspace/release-ops).
3. Lightweight Local Runtime: Running Switch Core locally (port 42015) alongside our compiled Rust CLI allowed the entire 3-agent + AST verification pipeline to run comfortably on an 8 GB Linux laptop with zero cloud infrastructure dependencies.

What Got in the Way (And How We Worked Around It):
1. Issue #1097 (External Chat Bridge Document Rendering): Mattermost bridges did not render native Switch room documents cleanly. We worked around this in SwitchGuard by serializing unified git diffs, AST rule verdicts, and SHA-256 audit receipts as compact in-thread Markdown blocks.
2. Issue #1226 (ACP Channel Splitting on Long Tracebacks): Verbose pytest stack traces triggered multi-message splitting over ACP channels, which could prematurely wake downstream agents. We enforced strict traceback compaction (<= 30 lines and < 1,500 characters) inside @sre-repro before posting to #sre-war-room.

Upstream Contributions Submitted to sandbox-quantum/switch:
1. PR #1566 (Closes Issue #827 — Supabase Service Connector): Added core/switch_core/connections/catalog/supabase/ using Shape 1 (remote MCP server at https://mcp.supabase.com/mcp with dynamic OAuth client registration, ?project_ref= scoping, and read-only default permissions; 171/171 loader tests passing).
2. PR #1659 (Closes Issue #837 — Trello Remote MCP Connector): Added core/switch_core/connections/catalog/trello/ with RFC 7591 dynamic OAuth registration and two-tier scope separation (8-scope read-only default vs. 12-scope write escalation; 220/220 gateway tests passing).

What Switch Should Build Next:
1. Native Pre-Dispatch Exit-Code Hooks: Allow room templates to declare a local binary hook (like switchguard-cli verify-diff) that must return exit code 0 before an agent's message or git commit is broadcast to the room.
2. Channel-Level Ingress Deduplication: Built-in fingerprint throttling on webhook/telemetry channels so a 10,000-event production alert storm doesn't trigger 10,000 parallel agent turns.
```

---

## Block 4: YouTube Studio Subtitles Transcript (`https://youtu.be/a3mLn3PMPjo`)

*Copy and paste the exact blocks below into **YouTube Studio $\rightarrow$ Subtitles $\rightarrow$ Auto-sync** or use as an SRT/VTT caption track:*

```text
0:00
Giving autonomous SRE agents unconstrained shell access fails in production:

0:05
raw traces leak customer secrets to cloud APIs,

0:08
prompt injection coerces agents into executing arbitrary commands,

0:11
and alert storms cause token bankruptcy.

0:14
SwitchGuard SRE enforces directory-isolated Switch Console agents,

0:18
gated at the OS boundary by a high-speed compiled Rust verifier.

0:23
We inject incident 8041 into the war room.

0:26
Sentinel invokes our Rust scrubber,

0:29
redacting JWTs, emails, and IPs into salted HMAC tokens while preserving the software version,

0:35
then locks the deduplication index via POSIX fcntl.

0:39
Routing to Repro, it follows strict TDD:

0:42
writing the failing reproduction test first in test_cart,

0:46
then clamping the negative subtotal in cart_service.

0:50
Before requesting approval, it executes switchguard-cli verify-diff,

0:55
clearing all ten AST and syntax guardrails in nine milliseconds.

0:59
The Incident Commander posts Approved.

1:02
Clerk evaluates four pre-release gates, packages the unified patch,

1:05
generates an attestation receipt (designed to be bound to a TEE attestation; not implemented),

1:08
and anchors a SHA-256 hash-chained entry to the tamper-evident release audit ledger.

1:13
Now we simulate an adversarial prompt injection attack under incident 8043.

1:17
An attacker injects an instruction override inside raw telemetry headers

1:21
to coerce the agent into executing curl pipe sh.

1:24
Even if a compromised LLM attempts to insert an os.system backdoor or split tokens across lines,

1:30
our compiled Rust verifier walks Python's native abstract syntax tree,

1:34
trips security rule AST-SEC-02 with Exit Code 2,

1:37
and automatically reverts the sandbox to clean HEAD.

1:41
Our seven-layer mega test suite validates thirty deterministic assertions:

1:45
thirty-two concurrent alert-storm workers with zero data corruption,

1:48
multiline AST defense, and nine millisecond diff latency.

1:51
We also contributed upstream connectors for Supabase PR 1566 and Trello PR 1659.

1:54
SwitchGuard SRE: provable safety for autonomous operations.
```

---

## Block 5: Official #HowISwitch Post for X (Twitter)

### Option A: Complete Standalone Post (Recommended for Single Post / Long-Form)
```text
Giving autonomous AI agents unconstrained shell access fails in production:
❌ Raw crash logs leak customer JWTs & AWS keys
❌ Telemetry headers prompt-inject agents into `curl | sh` backdoors
❌ Alert storms cause token bankruptcy & race conditions

Here is #HowISwitch to build autonomous SRE with real OS-boundary guardrails:

Meet SwitchGuard SRE 🛡️⚡
A 3-agent war room on Switch Console gated at the operating system boundary by a high-speed compiled Rust verifier (switchguard-cli):

1. Telemetry Intake (@sre-sentinel): Scrubs secrets to salted HMAC tokens in 8.92ms core (10.96ms end-to-end), preserves version strings against IPv4 collisions, and enforces O(1) hash-table deduplication under POSIX fcntl.flock—suppressing 32-worker alert storms with zero duplicate LLM calls.
2. Code Sandbox (@sre-repro): Strict TDD (failing pytest first) + 49.53ms core (51.47ms end-to-end) AST diff gate (blocks eval/exec, multiline os.system splits, untracked conftest backdoors, and assert deletions) + 2-strike circuit breaker.
3. Release Ops (@sre-clerk): Human-gated release authority. Verifies 5 checks, packages unified patches, generates attestation receipts (designed to be bound to a TEE attestation; not implemented), and anchors a keyed HMAC-SHA256 chain from genesis.

We also contributed two upstream core connectors to sandbox-quantum/switch:
• PR #1566: Supabase Service Connections v2 (Closes #827, 171/171 tests)
• PR #1659: Trello Remote MCP Connector (Closes #837, 220/220 tests)

📺 1:57 Demo Video: https://youtu.be/a3mLn3PMPjo
📖 Interactive Blog: https://anshulkaocde123.github.io/switchguard-sre/blog.html
💻 GitHub (30/30 Tests Green): https://github.com/Anshulkaocde123/switchguard-sre

#HowISwitch #AI #RustLang #DevOps #SRE #MachineLearning #AutonomousAgents
```

### Option B: 5-Tweet Technical Thread

#### Tweet 1 (The Hook & Video)
```text
Giving autonomous AI agents unconstrained shell access fails in production:
- Crash logs leak customer JWTs & AWS keys to cloud LLM APIs
- Telemetry prompt-injects agents into `curl | sh` backdoors
- Alert storms burn thousands of dollars in API credits

Here is #HowISwitch to fix it 🧵👇

📺 Watch the 1:57 execution: https://youtu.be/a3mLn3PMPjo
```

#### Tweet 2 (The 3-Ring Architecture)
```text
Instead of a single unconstrained agent, SwitchGuard SRE runs 3 directory-isolated Switch Console agents in #sre-war-room:

• @sre-sentinel (/workspace/telemetry): 0 access to app code. Scrubs secrets in 8.92ms core & dedups O(1) under POSIX fcntl.flock.
• @sre-repro (/workspace/sandbox-app): TDD reproduction & surgical fixing.
• @sre-clerk (/workspace/release-ops): Human-gated release & audit.

#HowISwitch
```

#### Tweet 3 (Compiled Security Verifier with AST Guardrails)
```text
Why does agent safety fail? Prompts can be jailbroken.

We built switchguard-cli in compiled Rust.
In 49.53ms core (51.47ms end-to-end) p50, it combines unified diff scanning with Python's native AST (ast.walk) to enforce 16 rules:
- Blocks eval/exec & os.system splits
- Blocks subprocess & dynamic imports
- Blocks network exfiltration & unsafe FS writes
- Anti-reward-hacking: blocks test/assert deletions
- MAX_ATTEMPTS=2 circuit breaker

#HowISwitch
```

#### Tweet 4 (Tamper-Evident SHA-256 Audit Chain)
```text
Automated releases need non-repudiable proof.

Every hotfix release is cryptographically linked into RELEASE_AUDIT.log:
ChainHash_n = HMAC-SHA256(key, ChainHash_{n-1} || Timestamp_n || PatchSHA256_n) from genesis (64 zeros).

Every release generates an attestation manifest binding the Rust binary & patch SHA-256 digests (designed to be bound to a TEE attestation; not implemented).

#HowISwitch
```

#### Tweet 5 (Upstream Switch Contributions & Live Links)
```text
We also contributed 2 core service connectors back to sandbox-quantum/switch:
• PR #1566: Supabase Service Connector (Closes #827, 171/171 tests)
• PR #1659: Trello Remote MCP Connector (Closes #837, 220/220 tests)

Check out the project:
📖 Deep Dive Blog: https://anshulkaocde123.github.io/switchguard-sre/blog.html
💻 GitHub (30/30 tests pass): https://github.com/Anshulkaocde123/switchguard-sre

#HowISwitch
```
