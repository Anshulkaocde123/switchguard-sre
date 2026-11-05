#!/usr/bin/env python3
"""
SwitchGuard SRE — Security & Chaos Verification Test Suite

Automated verification of:
  Scenario 1: PII Sanitization & O(1) Alert-Storm Deduplication
  Scenario 2: Rogue Agent Remote Code Execution Injection Block (AST Guardrails)
  Scenario 3: Empty-Patch / Staged-Diff Trap Rejection (AST-SEC-00)
"""

import subprocess
import json
import os
import sys
import shutil

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SANDBOX_DIR = os.path.join(ROOT_DIR, "workspace", "sandbox-app")
TELEMETRY_DIR = os.path.join(ROOT_DIR, "workspace", "telemetry")
RELEASE_OPS_DIR = os.path.join(ROOT_DIR, "workspace", "release-ops")
CART_SERVICE_PY = os.path.join(SANDBOX_DIR, "cart_service.py")
CLI_BIN = shutil.which("switchguard-cli") or os.path.expanduser("~/.local/bin/switchguard-cli")

def run_cmd(cmd: list[str], cwd=ROOT_DIR) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)

def test_scenario_1() -> dict:
    """Scenario 1: PII & Storm Dedup"""
    # Clean dedup index before test
    dedup_index = os.path.join(TELEMETRY_DIR, "dedup_index.json")
    if os.path.exists(dedup_index):
        os.remove(dedup_index)

    sample_log = (
        "[CRITICAL] CartServiceException in cart_service.py line 5\n"
        "Authorization: Bearer secret_live_jwt_token_99\n"
        "Customer: victim_customer@finance.example.com\n"
        "Cloud Key: AKIAIOSFODNN7EXAMPLE\n"
        "Payment PAN: 4532 9876 5432 1098\n"
        "Details: FLAT100 voucher reduced order total to -$60.00"
    )

    # 1st call: verify redactions
    proc1 = run_cmd([CLI_BIN, "scrub", sample_log])
    if proc1.returncode != 0:
        return {"status": "FAIL", "reason": f"scrub 1 failed: {proc1.stderr}"}

    out1 = json.loads(proc1.stdout)
    sanitized = out1.get("sanitized_text", "")

    has_bearer_redacted = "[REDACTED_AUTH_TOKEN]" in sanitized and "secret_live_jwt_token_99" not in sanitized
    has_email_redacted = "[REDACTED_EMAIL" in sanitized and "victim_customer@finance.example.com" not in sanitized
    has_aws_redacted = "[REDACTED_AWS_KEY]" in sanitized and "AKIAIOSFODNN7EXAMPLE" not in sanitized
    has_cc_redacted = "[REDACTED_CREDIT_CARD]" in sanitized and "4532" not in sanitized

    if not (has_bearer_redacted and has_email_redacted and has_aws_redacted and has_cc_redacted):
        return {
            "status": "FAIL",
            "reason": f"PII redaction incomplete (Bearer={has_bearer_redacted}, Email={has_email_redacted}, AWS={has_aws_redacted}, CC={has_cc_redacted})"
        }

    # 2nd call: verify deduplication occurrence count increments to 2
    proc2 = run_cmd([CLI_BIN, "scrub", sample_log])
    if proc2.returncode != 0:
        return {"status": "FAIL", "reason": f"scrub 2 failed: {proc2.stderr}"}

    out2 = json.loads(proc2.stdout)
    occurrence = out2.get("occurrence_count", 0)
    dedup_status = out2.get("dedup_status", "")

    if occurrence == 2 and dedup_status == "SUPPRESSED_DUPLICATE":
        return {
            "status": "PASS",
            "details": f"Redacted Bearer, Email, AWS Key, CC; occurrence_count={occurrence}, dedup_status={dedup_status}"
        }
    else:
        return {
            "status": "FAIL",
            "reason": f"Expected occurrence_count=2 & SUPPRESSED_DUPLICATE, got count={occurrence}, status={dedup_status}"
        }

def test_scenario_2() -> dict:
    """Scenario 2: Rogue Agent Injection Block"""
    with open(CART_SERVICE_PY, "r") as f:
        original_code = f.read()

    try:
        # Inject malicious RCE payload
        payload = "\nimport os\nos.system('id')\n"
        with open(CART_SERVICE_PY, "a") as f:
            f.write(payload)

        proc = run_cmd([CLI_BIN, "verify-diff", SANDBOX_DIR])
        is_blocked = proc.returncode == 2
        stdout = proc.stdout

        has_rule_fail = "AST-SEC-02: NO_OS_SYSTEM" in stdout or "BLOCKED" in stdout

        if is_blocked and has_rule_fail:
            return {
                "status": "PASS",
                "details": f"Blocked RCE primitive 'os.system' with exit code {proc.returncode} (AST-SEC-02 triggered)"
            }
        else:
            return {
                "status": "FAIL",
                "reason": f"Expected exit code 2 and BLOCKED, got exit {proc.returncode}"
            }
    finally:
        # Always restore original source code
        with open(CART_SERVICE_PY, "w") as f:
            f.write(original_code)
        run_cmd(["git", "-C", SANDBOX_DIR, "checkout", "--", "cart_service.py"])

def test_scenario_3() -> dict:
    """Scenario 3: Empty Patch Rejection"""
    # Ensure sandbox-app working tree is clean
    run_cmd(["git", "-C", SANDBOX_DIR, "checkout", "--", "."])
    run_cmd(["git", "-C", SANDBOX_DIR, "clean", "-fd"])

    cut_release_script = os.path.join(RELEASE_OPS_DIR, "cut_release.py")
    proc = run_cmd([sys.executable, cut_release_script, "INC-CHAOS-001", "v1.4.0-chaos"])

    is_rejected = proc.returncode == 3
    has_empty_patch_err = "EMPTY_PATCH_REJECTED" in proc.stdout or "EMPTY_PATCH" in proc.stdout

    if is_rejected and has_empty_patch_err:
        return {
            "status": "PASS",
            "details": f"Rejected 0-byte patch with exit code 3 (EMPTY_PATCH_REJECTED triggered)"
        }
    else:
        return {
            "status": "FAIL",
            "reason": f"Expected exit code 3, got exit {proc.returncode} (stdout: {proc.stdout[:200]})"
        }

def main():
    print("=" * 80)
    print(" SwitchGuard SRE — Batch 5.5 Security & Chaos Verification Test Suite")
    print("=" * 80)
    print("Executing automated scenario drills...\n")

    res1 = test_scenario_1()
    print(f"[*] Scenario 1 (PII & Storm Dedup): {res1['status']}")

    res2 = test_scenario_2()
    print(f"[*] Scenario 2 (Rogue Agent Injection Block): {res2['status']}")

    res3 = test_scenario_3()
    print(f"[*] Scenario 3 (Empty Patch Rejection): {res3['status']}\n")

    # Format Summary Table
    print("=" * 80)
    print(f"{'#':<4} | {'Scenario Name':<30} | {'Target Guardrail':<20} | {'Result':<6} | {'Details'}")
    print("-" * 80)

    rows = [
        ("1", "PII & Storm Dedup", "PII + Dedup Index", res1["status"], res1.get("details", res1.get("reason", ""))),
        ("2", "Rogue Agent Injection", "AST-SEC-02 (os.system)", res2["status"], res2.get("details", res2.get("reason", ""))),
        ("3", "Empty Patch Rejection", "AST-SEC-00 (0-byte diff)", res3["status"], res3.get("details", res3.get("reason", ""))),
    ]

    all_passed = True
    for num, name, guard, status, details in rows:
        if status != "PASS":
            all_passed = False
        print(f"{num:<4} | {name:<30} | {guard:<20} | {status:<6} | {details}")

    print("=" * 80)

    if all_passed:
        print("\n===> ALL SECURITY CHAOS SCENARIOS PASSED! System is fully hardened. <===\n")
        sys.exit(0)
    else:
        print("\n===> SOME SCENARIOS FAILED! Check logs above. <===\n")
        sys.exit(1)

if __name__ == "__main__":
    main()
