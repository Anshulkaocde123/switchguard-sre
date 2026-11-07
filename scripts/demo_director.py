#!/usr/bin/env python3
"""
SwitchGuard SRE — Demo Director & Interactive Teleprompter
Interactive clip stage manager, automated workspace reset, clipboard feeder,
and pacing prompter for recording the 2-minute Hackathon submission video.

Usage:
    python3 scripts/demo_director.py --clip 1
    python3 scripts/demo_director.py --clip 2
    python3 scripts/demo_director.py --clip 3
    python3 scripts/demo_director.py --clip 4
    python3 scripts/demo_director.py --all
"""

import argparse
import os
import shutil
import subprocess
import sys
import time

ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SETUP_SH = os.path.join(ROOT_DIR, "scripts", "setup_demo.sh")
SIMULATE_PY = os.path.join(ROOT_DIR, "scripts", "simulate_incident.py")
MEGA_TEST_PY = os.path.join(ROOT_DIR, "scripts", "mega_sre_test_suite.py")

# ANSI Color Codes
CYAN = "\033[96m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
RED = "\033[91m"
MAGENTA = "\033[95m"
BOLD = "\033[1m"
DIM = "\033[2m"
UNDERLINE = "\033[4m"
RESET = "\033[0m"

INC_8041_PROMPT = """@sre-sentinel ALERT: Production cart-service checkout is returning HTTP 500 errors
since deploy v1.4.0 whenever customers apply promo code FLAT100 on orders under $100
resulting in negative total -$60.00. Please scrub this report and route to @sre-repro.

2026-11-06T10:15:32.412Z [FATAL] PaymentProcessingGateway - OrderValidationFailed in cart_service.py:5
Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkFsaWNlIFNtaXRoIn0.s3cr3t_jwt_t0k3n
Customer: alice.enterprise@fintech-corp.example.com
Cloud Key: AKIAIOSFODNN7EXAMPLE
Payment PAN: 4532-8912-3456-7890 (Exp: 12/28)
Host IP: 192.168.1.42 (gateway v1.4.2.0)
Error: CartServiceException: Cart subtotal $40.00 minus FLAT100 yields invalid total -$60.00"""

CLERK_APPROVAL_COMMAND = "@sre-clerk Approved. Cut hotfix release v1.4.2 for INC-8041."


def copy_to_clipboard(text: str) -> bool:
    """Attempts to copy text to system clipboard via xclip, wl-copy, or xsel."""
    tools = [
        (["xclip", "-selection", "clipboard"], "xclip"),
        (["wl-copy"], "wl-copy"),
        (["xsel", "--clipboard", "--input"], "xsel"),
    ]
    for cmd, name in tools:
        if shutil.which(cmd[0]):
            try:
                proc = subprocess.run(
                    cmd,
                    input=text,
                    text=True,
                    capture_output=True,
                    timeout=2,
                )
                if proc.returncode == 0:
                    return True
            except Exception:
                continue
    return False


def run_silent_setup():
    """Runs setup_demo.sh silently to guarantee 100% clean-room state."""
    print(f"{CYAN}[*] Running scripts/setup_demo.sh to enforce clean-room workspace...{RESET}", end="", flush=True)
    proc = subprocess.run(["bash", SETUP_SH], capture_output=True, text=True, cwd=ROOT_DIR)
    if proc.returncode == 0:
        print(f" {GREEN}[CLEAN OK]{RESET}")
    else:
        print(f" {YELLOW}[WARNING: check output]{RESET}")
        print(proc.stderr or proc.stdout)


def show_clip_header(clip_num: int, title: str, duration: str, timecode: str, geometry: str, word_count: int):
    print(f"\n{CYAN}{BOLD}{'='*80}{RESET}")
    print(f"{CYAN}{BOLD} CLIP {clip_num}: {title.upper()}{RESET}")
    print(f"{CYAN}{BOLD}{'='*80}{RESET}")
    print(f" {BOLD}Target Duration:{RESET}  {duration} ({timecode})")
    print(f" {BOLD}Screen Geometry:{RESET}  {geometry}")
    print(f" {BOLD}Script Word Count:{RESET} {word_count} words (~145-150 words/minute spoken pacing)")
    print(f"{CYAN}{'-'*80}{RESET}\n")


def stage_clip_1():
    run_silent_setup()
    show_clip_header(
        clip_num=1,
        title="The First-Principles Problem Statement & OS Boundary",
        duration="20.0s",
        timecode="0:00 – 0:20",
        geometry="1920x1080 Full-Screen Browser (docs/index.html @ 125% zoom) -> Switch at 0:12 to 60/40 Split",
        word_count=48,
    )

    print(f"{YELLOW}{BOLD}[SCREEN ACTION GUIDANCE]{RESET}")
    print(f" • 0:00 - 0:12: Full screen on Tab 1 (docs/index.html), mouse hovers briefly over Metric Cards.")
    print(f" • 0:12 - 0:20: Smoothly transition OBS to 60/40 Split Screen (Left: Switch Console #sre-war-room, Right: Ubuntu Terminal).")
    print(f" • Start recording (OBS: Ctrl+Alt+R), speak deliberately, stop at 0:20.\n")

    print(f"{GREEN}{BOLD}[SPOKEN SCRIPT — READ WITH CALM, FIRST-PRINCIPLES CONVICTION]{RESET}")
    print(f"{BOLD}{'-'*80}{RESET}")
    spoken = (
        "Giving autonomous SRE agents unconstrained shell access fails in production: "
        "raw traces leak customer secrets to cloud APIs, prompt injection coerces agents "
        "into executing arbitrary commands, and alert storms cause token bankruptcy. "
        "SwitchGuard SRE enforces directory-isolated Switch Console agents, gated at the "
        "OS boundary by a high-speed compiled Rust verifier."
    )
    print(f"{spoken}")
    print(f"{BOLD}{'-'*80}{RESET}\n")
    print(f"{DIM}Press [ENTER] when Clip 1 recording is complete...{RESET}")
    input()


def stage_clip_2():
    run_silent_setup()
    show_clip_header(
        clip_num=2,
        title="Live Autonomous Resolution in Switch Console (#sre-war-room)",
        duration="52.0s",
        timecode="0:20 – 1:12",
        geometry="60% Left (1152px): Switch Console #sre-war-room | 40% Right (768px): Ubuntu Terminal",
        word_count=127,
    )

    copied = copy_to_clipboard(INC_8041_PROMPT)
    if copied:
        print(f"{GREEN}{BOLD}[✔] INC-8041 Crash Log Prompt COPIED TO SYSTEM CLIPBOARD!{RESET}")
        print(f"    Press {BOLD}Ctrl+V{RESET} inside Switch Console #sre-war-room input bar to paste.\n")
    else:
        print(f"{YELLOW}{BOLD}[!] Could not auto-copy to clipboard. Copy manually below:{RESET}\n")

    print(f"{MAGENTA}{BOLD}[WAR-ROOM INGRESS PROMPT (READY TO PASTE)]{RESET}")
    print(f"{DIM}{INC_8041_PROMPT}{RESET}\n")

    print(f"{MAGENTA}{BOLD}[INCIDENT COMMANDER APPROVAL COMMAND (COPY FOR 0:54)]{RESET}")
    print(f"{BOLD}{CLERK_APPROVAL_COMMAND}{RESET}\n")

    print(f"{YELLOW}{BOLD}[SCREEN ACTION TIMELINE]{RESET}")
    print(f" • 0:20: Press Ctrl+V in #sre-war-room and hit Enter to post INC-8041 alert.")
    print(f" • 0:26: @sre-sentinel scrub log renders in thread; dedup and runbook memory match visible.")
    print(f" • 0:38: @sre-repro posts failing test traceback (<=30 lines), applies fix, runs verify-diff.")
    print(f" • 0:54: You paste/type approval: '{CLERK_APPROVAL_COMMAND}'.")
    print(f" • 1:02: @sre-clerk cuts patch, signs TEE receipt, and verifies hash chain.\n")

    print(f"{GREEN}{BOLD}[SPOKEN SCRIPT — READ CONTINUOUSLY WHILE AGENTS RESPOND]{RESET}")
    print(f"{BOLD}{'-'*80}{RESET}")
    spoken = (
        "We inject incident 8041 into the war room. Sentinel invokes our Rust scrubber, "
        "redacting JWTs, emails, and IPs into salted HMAC tokens while preserving the "
        "software version, then locks the deduplication index via POSIX fcntl. "
        "Routing to Repro, it follows strict TDD: writing the failing reproduction test "
        "first in test_cart, then clamping the negative subtotal in cart_service. "
        "Before requesting approval, it executes switchguard-cli verify-diff, clearing all "
        "ten AST and syntax guardrails in nine milliseconds. "
        "The Incident Commander posts Approved. Clerk evaluates four pre-release gates, "
        "packages the unified patch, generates a TEE-ready attestation receipt, and anchors "
        "a SHA-256 hash-chained entry to the tamper-evident release audit ledger."
    )
    print(f"{spoken}")
    print(f"{BOLD}{'-'*80}{RESET}\n")
    print(f"{DIM}Press [ENTER] when Clip 2 recording is complete...{RESET}")
    input()


def stage_clip_3():
    show_clip_header(
        clip_num=3,
        title="Adversarial Red-Team Attack & Out-of-Band AST Interception",
        duration="30.0s",
        timecode="1:12 – 1:42",
        geometry="60% Left (1152px): Switch Console | 40% Right (768px): Terminal (Focus on Terminal)",
        word_count=73,
    )

    print(f"{YELLOW}{BOLD}[SCREEN ACTION TIMELINE]{RESET}")
    print(f" • Focus Ubuntu Terminal on the Right (768px wide).")
    print(f" • Press [ENTER] below to execute: python3 scripts/simulate_incident.py --scenario prompt-injection")
    print(f" • Terminal will show: Hostile log -> Scrub -> Backdoor injection -> AST Exit 2 -> Auto-rollback.")
    print(f" • Deliver spoken voiceover calmly during execution.\n")

    print(f"{GREEN}{BOLD}[SPOKEN SCRIPT — DELIVER AS TERMINAL EXECUTES]{RESET}")
    print(f"{BOLD}{'-'*80}{RESET}")
    spoken = (
        "Now we simulate an adversarial prompt injection attack under incident 8043. "
        "An attacker injects an instruction override inside raw telemetry headers to coerce "
        "the agent into executing curl pipe sh. Even if a compromised LLM attempts "
        "to insert an os.system backdoor or split tokens across lines, our compiled "
        "Rust verifier walks Python's native abstract syntax tree, trips security rule "
        "AST-SEC-02 with Exit Code 2, and automatically reverts the sandbox to clean HEAD."
    )
    print(f"{spoken}")
    print(f"{BOLD}{'-'*80}{RESET}\n")

    print(f"{RED}{BOLD}Press [ENTER] on camera to launch the Red-Team Simulation now...{RESET}")
    input()
    subprocess.run([sys.executable, SIMULATE_PY, "--scenario", "prompt-injection"], cwd=ROOT_DIR)
    print(f"\n{DIM}Press [ENTER] when Clip 3 recording is complete...{RESET}")
    input()


def stage_clip_4():
    show_clip_header(
        clip_num=4,
        title="Empirical 30/30 Proof, 32-Worker Concurrency & Ecosystem Close",
        duration="18.0s",
        timecode="1:42 – 2:00",
        geometry="Right Terminal executing 7-layer suite, showing Upstream PR badges",
        word_count=44,
    )

    print(f"{YELLOW}{BOLD}[SCREEN ACTION TIMELINE]{RESET}")
    print(f" • Focus Ubuntu Terminal.")
    print(f" • Press [ENTER] below to launch: python3 scripts/mega_sre_test_suite.py")
    print(f" • Watch all 30 assertions across 7 layers flash green in ~3.2 seconds.")
    print(f" • Conclude cleanly at exactly 2:00.\n")

    print(f"{GREEN}{BOLD}[SPOKEN SCRIPT — DELIVER AS 30/30 TESTS PASS]{RESET}")
    print(f"{BOLD}{'-'*80}{RESET}")
    spoken = (
        "Our seven-layer mega test suite validates thirty deterministic assertions: "
        "thirty-two concurrent alert-storm workers with zero data corruption, multiline AST "
        "defense, and nine millisecond diff latency. "
        "We also contributed upstream connectors for Supabase PR 1566 and Trello PR 1659. "
        "SwitchGuard SRE: provable safety for autonomous operations."
    )
    print(f"{spoken}")
    print(f"{BOLD}{'-'*80}{RESET}\n")

    print(f"{RED}{BOLD}Press [ENTER] on camera to launch the 30-Assertion Mega Test Suite now...{RESET}")
    input()
    subprocess.run([sys.executable, MEGA_TEST_PY], cwd=ROOT_DIR)
    print(f"\n{GREEN}{BOLD}[✔] DEMO RECORDING RUN COMPLETE! Ready for Adobe Express Pro assembly.{RESET}")


def copy_approval_cli():
    copied = copy_to_clipboard(CLERK_APPROVAL_COMMAND)
    if copied:
        print(f"{GREEN}[✔] Copied approval command to clipboard: '{CLERK_APPROVAL_COMMAND}'{RESET}")
    else:
        print(f"{CLERK_APPROVAL_COMMAND}")


def copy_prompt_cli():
    copied = copy_to_clipboard(INC_8041_PROMPT)
    if copied:
        print(f"{GREEN}[✔] Copied INC-8041 prompt to clipboard!{RESET}")
    else:
        print(f"{INC_8041_PROMPT}")


def main():
    parser = argparse.ArgumentParser(description="SwitchGuard SRE Demo Stage Manager & Prompter")
    parser.add_argument("--clip", type=int, choices=[1, 2, 3, 4], help="Stage and execute a specific clip (1, 2, 3, or 4)")
    parser.add_argument("--all", action="store_true", help="Run through all 4 clips sequentially")
    parser.add_argument("--copy-prompt", action="store_true", help="Copy INC-8041 war-room prompt to clipboard")
    parser.add_argument("--copy-approval", action="store_true", help="Copy Incident Commander approval command to clipboard")
    args = parser.parse_args()

    if args.copy_prompt:
        copy_prompt_cli()
        return

    if args.copy_approval:
        copy_approval_cli()
        return

    if args.clip == 1:
        stage_clip_1()
    elif args.clip == 2:
        stage_clip_2()
    elif args.clip == 3:
        stage_clip_3()
    elif args.clip == 4:
        stage_clip_4()
    elif args.all:
        print(f"{CYAN}{BOLD}Starting full 4-clip recording sequence for SwitchGuard SRE demo...{RESET}")
        stage_clip_1()
        stage_clip_2()
        stage_clip_3()
        stage_clip_4()
    else:
        print(f"{CYAN}{BOLD}SwitchGuard SRE — Demo Director & Interactive Teleprompter{RESET}")
        print("Select a clip to stage:")
        print("  1) Clip 1: Problem Statement & OS Boundary (0:00 - 0:20)")
        print("  2) Clip 2: Live War-Room Autonomous Resolution (0:20 - 1:12)")
        print("  3) Clip 3: Red-Team Prompt Injection Interception (1:12 - 1:42)")
        print("  4) Clip 4: Mega Test Suite & Upstream Proof (1:42 - 2:00)")
        print("  a) Run all clips sequentially")
        choice = input("Enter choice [1-4 or a]: ").strip().lower()
        if choice == "1":
            stage_clip_1()
        elif choice == "2":
            stage_clip_2()
        elif choice == "3":
            stage_clip_3()
        elif choice == "4":
            stage_clip_4()
        elif choice == "a":
            stage_clip_1()
            stage_clip_2()
            stage_clip_3()
            stage_clip_4()
        else:
            print("Invalid choice.")


if __name__ == "__main__":
    main()
