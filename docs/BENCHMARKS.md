# SwitchGuard SRE — Reproducible Benchmark Report

Generated on `2026-11-07T22:26:48.434632+00:00` using `scripts/benchmark.py` ($N=50$ iterations per target).

## 1. System & Environment Specifications

- **CPU Model:** 13th Gen Intel(R) Core(TM) i5-1335U
- **Operating System:** Linux 7.0.0-42-generic (x86_64)
- **Rust Toolchain:** `rustc 1.99.1 (58cf8f9c3 2026-10-13)`
- **Python Version:** `3.12.3`
- **Build Profile:** `release` (`--release` optimized)

## 2. Latency Measurement Attribution (Core vs. End-to-End)

> [!NOTE]
> **Why Core and End-to-End Differ:** Core processing measures the internal CPU execution time inside the compiled Rust binary (regex matching, SHA-256 digests, HMAC-SHA256 calculations, and hash-table lookups). End-to-end invocation measures the full subprocess lifecycle including OS `fork`/`exec`, dynamic linker initialization (`ld.so`), memory mapping, and stdout/stderr pipe communication.

> [!NOTE]
> **Precise Definition of O(1) Deduplication:** Alert storm deduplication is $O(1)$ expected time because fault fingerprints are computed as `SHA256(error_class || normalized_file_line)` and resolved via a hash-table index (`HashMap<String, DedupEntry>`), avoiding any linear scan over historic crash logs.

## 3. Measured Performance Summary

| Operation | Metric Layer | Samples ($N$) | Min | p50 (Median) | p95 | p99 | Max | StdDev |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **Scrub First Seen** | **Core Processing** | 50 | 4.275ms | **10.082ms** | 11.39ms | 11.922ms | 11.922ms | ±1.308ms |
| | **End-to-End CLI** | 50 | 5.694ms | **12.366ms** | 13.528ms | 14.192ms | 14.192ms | ±1.462ms |
| **Scrub Suppressed Duplicate** | **Core Processing** | 50 | 4.475ms | **8.922ms** | 12.853ms | 15.829ms | 15.829ms | ±2.545ms |
| | **End-to-End CLI** | 50 | 5.757ms | **10.959ms** | 15.161ms | 18.191ms | 18.191ms | ±2.904ms |
| **Verify Diff** | **Core Processing** | 50 | 41.609ms | **49.534ms** | 58.218ms | 69.859ms | 69.859ms | ±5.208ms |
| | **End-to-End CLI** | 50 | 42.985ms | **51.468ms** | 60.118ms | 71.584ms | 71.584ms | ±5.326ms |
| **Verify Audit** | **Core Processing** | 50 | 0.61ms | **1.968ms** | 2.26ms | 2.434ms | 2.434ms | ±0.42ms |
| | **End-to-End CLI** | 50 | 1.746ms | **3.867ms** | 4.298ms | 4.584ms | 4.584ms | ±0.781ms |

## 4. Key Takeaways & SLA Compliance

1. **Alert Storm Suppression:** Duplicate crashes are resolved in **8.922ms** core processing time (**15.161ms** p95 end-to-end), well within the 25ms SLA required for high-frequency alert floods.
2. **AST Diff Verification:** Full security diff verification runs in **49.534ms** core processing time (**60.118ms** p95 end-to-end).
3. **Cryptographic Audit Log Verification:** Keyed HMAC-SHA256 audit log validation executes in **1.968ms** core processing time.
