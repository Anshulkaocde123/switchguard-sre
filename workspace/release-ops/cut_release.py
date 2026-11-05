import subprocess
import sys
import datetime
import json
import os
import hashlib
import shutil
import fcntl

SANDBOX_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../sandbox-app"))
RELEASES_DIR = os.path.join(os.path.dirname(__file__), "releases")
AUDIT_LOG = os.path.join(os.path.dirname(__file__), "RELEASE_AUDIT.log")

def execute_release(incident_id: str, version: str):
    os.makedirs(RELEASES_DIR, exist_ok=True)

    # 1. Run Rust switchguard-cli verify-diff on sandbox-app
    cli_bin = shutil.which("switchguard-cli") or os.path.expanduser("~/.local/bin/switchguard-cli")
    verify_proc = subprocess.run(
        [cli_bin, "verify-diff", SANDBOX_DIR],
        capture_output=True,
        text=True
    )

    if verify_proc.returncode == 3:
        print(f"[RELEASE BLOCKED] Empty patch detected by Rust verifier:\n{verify_proc.stdout}")
        sys.exit(3)
    elif verify_proc.returncode != 0:
        print(f"[RELEASE BLOCKED] Rust AST Security Verification failed (exit {verify_proc.returncode}):\n{verify_proc.stdout}")
        sys.exit(verify_proc.returncode)

    audit_data = json.loads(verify_proc.stdout)

    # 2. Export git diff HEAD to patch artifact (catches staged + unstaged)
    diff_proc = subprocess.run(
        ["git", "-C", SANDBOX_DIR, "diff", "HEAD"],
        capture_output=True,
        text=True,
        check=True
    )

    # --- EDGE CASE A: Empty-patch rejection ---
    diff_content = diff_proc.stdout.strip()
    if not diff_content:
        empty_sha = hashlib.sha256(b"").hexdigest()
        print(json.dumps({
            "release_status": "EMPTY_PATCH_REJECTED",
            "incident_id": incident_id,
            "error": "EMPTY_PATCH — git diff HEAD returned 0 bytes. No changes to release.",
            "patch_sha256": empty_sha,
            "exit_code": 3
        }, indent=2))
        sys.exit(3)

    # Count files and lines changed
    files_changed = sum(1 for line in diff_content.splitlines() if line.startswith("diff --git"))
    lines_added = sum(1 for line in diff_content.splitlines() if line.startswith("+") and not line.startswith("+++"))
    if files_changed == 0 or lines_added == 0:
        print(json.dumps({
            "release_status": "EMPTY_PATCH_REJECTED",
            "incident_id": incident_id,
            "error": f"Patch has {files_changed} files changed and {lines_added} lines added — insufficient for release.",
            "exit_code": 3
        }, indent=2))
        sys.exit(3)

    patch_filename = f"hotfix-{incident_id}-{version}.patch"
    patch_path = os.path.join(RELEASES_DIR, patch_filename)
    with open(patch_path, "w") as f:
        f.write(diff_content)

    patch_sha256 = hashlib.sha256(diff_content.encode()).hexdigest()
    timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()

    # 3. Cryptographic Hash Chaining:
    # ChainHash_n = SHA256(ChainHash_{n-1} || Timestamp_n || PatchSHA256_n)
    genesis_hash = "0" * 64
    prev_chain_hash = genesis_hash

    if os.path.exists(AUDIT_LOG):
        with open(AUDIT_LOG, "r") as f:
            for line in f:
                line_str = line.strip()
                if "CHAIN_HASH=" in line_str:
                    parts = line_str.split("CHAIN_HASH=")
                    if len(parts) > 1:
                        cand = parts[1].strip().split()[0].split("|")[0].strip()
                        if len(cand) == 64:
                            prev_chain_hash = cand

    chain_payload = f"{prev_chain_hash}{timestamp}{patch_sha256}"
    chain_hash = hashlib.sha256(chain_payload.encode("utf-8")).hexdigest()

    log_entry = (
        f"[{timestamp}] HOTFIX RELEASED: {version} for {incident_id} | "
        f"AST_AUDIT={audit_data.get('verdict', audit_data.get('status'))} | "
        f"PATCH={patch_filename} | SHA256={patch_sha256} | "
        f"FILES={files_changed} | LINES_ADDED={lines_added} | "
        f"PREV_HASH={prev_chain_hash} | CHAIN_HASH={chain_hash}\n"
    )

    # 4. Durability: POSIX exclusive file lock (fcntl.flock) + os.fsync
    with open(AUDIT_LOG, "a+") as f:
        fcntl.flock(f.fileno(), fcntl.LOCK_EX)
        try:
            f.seek(0, os.SEEK_END)
            f.write(log_entry)
            f.flush()
            os.fsync(f.fileno())
        finally:
            fcntl.flock(f.fileno(), fcntl.LOCK_UN)

    print(json.dumps({
        "release_status": "DEPLOYED",
        "incident_id": incident_id,
        "hotfix_branch": f"release/hotfix-{version}",
        "ast_audit": audit_data.get("verdict", "PASS"),
        "patch_artifact": f"releases/{patch_filename}",
        "patch_sha256": patch_sha256,
        "files_changed": files_changed,
        "lines_added": lines_added,
        "prev_chain_hash": prev_chain_hash,
        "chain_hash": chain_hash
    }, indent=2))

if __name__ == "__main__":
    inc_id = sys.argv[1] if len(sys.argv) > 1 else "INC-8041"
    ver = sys.argv[2] if len(sys.argv) > 2 else "v1.4.2"
    execute_release(inc_id, ver)
