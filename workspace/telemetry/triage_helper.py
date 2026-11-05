import subprocess
import json
import sys
import datetime
import os
import shutil

TELEMETRY_DIR = os.path.dirname(os.path.abspath(__file__))
LEDGER_FILE = os.path.join(TELEMETRY_DIR, "incidents_ledger.md")

def run_triage(raw_log: str, incident_id: str = "INC-8041"):
    # 1. Invoke compiled Rust switchguard-cli binary
    cli_bin = shutil.which("switchguard-cli") or os.path.expanduser("~/.local/bin/switchguard-cli")
    proc = subprocess.run(
        [cli_bin, "scrub", raw_log],
        capture_output=True,
        text=True,
        check=True
    )
    data = json.loads(proc.stdout)

    # --- Alert-storm deduplication ---
    from alert_dedup import check_and_register
    dedup_result = check_and_register(data, incident_id)
    if dedup_result["status"] == "DUPLICATE":
        print(json.dumps({
            "triage_status": "SUPPRESSED_DUPLICATE",
            "incident_id": incident_id,
            "dedup": dedup_result,
        }, indent=2))
        return  # Suppress duplicate — do not log to ledger or dispatch

    # --- Incident state machine initialization ---
    from incident_state import init_incident
    state_result = init_incident(incident_id, agent="sre-sentinel")

    timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

    # 2. Maintain Markdown Ledger
    if not os.path.exists(LEDGER_FILE):
        with open(LEDGER_FILE, "w") as f:
            f.write("# SwitchGuard SRE — Sanitized Incidents Ledger\n\n")
            f.write("| Timestamp | Incident ID | Error Class | Redactions | SHA-256 Digest | Sanitized Summary |\n")
            f.write("| :--- | :--- | :--- | :--- | :--- | :--- |\n")

    summary_one_line = data.get("clean_payload", data.get("sanitized_text", "")).replace("\n", " ")
    sha = data.get("sha256", "UNKNOWN")[:12]
    redactions = data.get("redacted_count", data.get("redactions_applied", 0))
    err_class = data.get("error_classification", data.get("error_class", "UNKNOWN"))

    with open(LEDGER_FILE, "a") as f:
        f.write(f"| {timestamp} | `{incident_id}` | `{err_class}` | {redactions} | `{sha}...` | {summary_one_line} |\n")

    print(json.dumps({
        **data,
        "triage_status": "DISPATCHED",
        "incident_id": incident_id,
        "dedup": dedup_result,
        "state_machine": state_result,
    }, indent=2))

if __name__ == "__main__":
    raw_input = sys.argv[1] if len(sys.argv) > 1 else "Bearer secret123 user@example.com FLAT100 -$60.00"
    inc_id = sys.argv[2] if len(sys.argv) > 2 else "INC-8041"
    run_triage(raw_input, inc_id)
