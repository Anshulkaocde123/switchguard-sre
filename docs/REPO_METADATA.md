# Repository Metadata & Social Presentation

This document contains canonical metadata, descriptions, topic classifications, and social preview text for the SwitchGuard SRE repository.

---

## 1. Repository Description

> **Character limit**: $\le 160$ characters.

```text
Hardened autonomous SRE multi-agent incident response constrained by a deterministic Rust AST security gate and keyed HMAC release audit chains.
```

*(Exact length: 144 characters)*

---

## 2. Topic Tags

Suggested GitHub repository topic tags for indexing, discovery, and categorization:

```text
sre
autonomous-agents
rust
security-gate
incident-response
antigravity
switch
ast-security
prompt-injection-defense
circuit-breaker
tamper-evident
hmac-sha256
posix-locking
```

---

## 3. Social Preview Text (OpenGraph / Twitter Card)

### Title
```text
SwitchGuard SRE — Out-of-Band Deterministic Security Gate for Autonomous Agents
```

### Subtitle / Summary (2–3 sentences)
```text
Autonomous SRE agents cannot be secured by prompt instructions alone. SwitchGuard SRE deploys a compiled Rust verifier (v0.4.0) that enforces 16 AST security rules, O(1) canonical fault deduplication, untrusted data envelopes, and keyed HMAC-SHA256 audit chains across multi-agent incident workflows on Switch Console and Google Antigravity ACP.
```

---

## 4. Key Highlights for Hackathon / Project Directory

- **Core Thesis**: Machine-enforced structural invariants over prompt-engineered guidelines.
- **Empirical Proof**: 24-case real-agent evaluation showing adversarial attack success rate dropped from 100% to 6.2% (93.8% block rate) with 0% false rejections on benign fixes.
- **Performance**: Sub-millisecond core deduplication ($<0.5\text{ms}$), 8.92ms core diff parsing, 32-worker concurrent storm resilience under POSIX `flock`.
- **Integrity**: RFC 2104 keyed HMAC-SHA256 release audit trail with truncation and tampering detection.
