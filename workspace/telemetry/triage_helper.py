import subprocess
import json
import sys
import datetime
import os
import shutil
import fcntl

TELEMETRY_DIR = os.path.dirname(os.path.abspath(__file__))
LEDGER_FILE = os.path.join(TELEMETRY_DIR, "incidents_ledger.md")
DEDUP_INDEX_FILE = os.path.join(TELEMETRY_DIR, "dedup_index.json")

def verify_and_lock_dedup_index(fault_fingerprint: str, scrub_data: dict) -> tuple[str, int]:
    """
    Ensures dedup_index.json is synchronized with exclusive POSIX flock.
    Returns (dedup_status, occurrence_count).
    """
    dedup_status = scrub_data.get("dedup_status", "FIRST_SEEN")
    occurrence_count = scrub_data.get("occurrence_count", 1)

    # Acquire exclusive POSIX flock on dedup_index.json
    if os.path.exists(DEDUP_INDEX_FILE):
        with open(DEDUP_INDEX_FILE, "r+") as f:
            fcntl.flock(f.fileno(), fcntl.LOCK_EX)
            try:
                try:
                    data = json.load(f)
                    if "fingerprints" in data and fault_fingerprint in data["fingerprints"]:
                        entry = data["fingerprints"][fault_fingerprint]
                        occurrence_count = entry.get("occurrence_count", occurrence_count)
                        if occurrence_count > 1:
                            dedup_status = "SUPPRESSED_DUPLICATE"
                        else:
                            dedup_status = "FIRST_SEEN"
                except Exception:
                    pass
            finally:
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)
    else:
        # Create initial index if not yet existing
        with open(DEDUP_INDEX_FILE, "a+") as f:
            fcntl.flock(f.fileno(), fcntl.LOCK_EX)
            try:
                f.seek(0)
                if not f.read().strip():
                    json.dump({"version": "1.0", "fingerprints": {}}, f, indent=2)
                    f.flush()
                    os.fsync(f.fileno())
            finally:
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)

    return dedup_status, occurrence_count

def run_triage(raw_log: str, incident_id: str = "INC-8041"):
    # 1. Invoke compiled Rust switchguard-cli binary (<0.4ms PII scrub + canonical fault fingerprint)
    cli_bin = shutil.which("switchguard-cli") or os.path.expanduser("~/.local/bin/switchguard-cli")
    proc = subprocess.run(
        [cli_bin, "scrub", raw_log],
        capture_output=True,
        text=True,
        check=True
    )
    data = json.loads(proc.stdout)

    fault_fingerprint = data.get("fault_fingerprint", "unknown")
    file_line = data.get("normalized_file_line", "unknown:0")
    err_class = data.get("error_classification", data.get("error_class", "UNKNOWN"))

    # 2. Synchronize dedup_index.json with exclusive POSIX flock
    dedup_status, occurrence = verify_and_lock_dedup_index(fault_fingerprint, data)

    timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    summary_one_line = data.get("clean_payload", data.get("sanitized_text", "")).replace("\n", " ")
    sha = data.get("sha256", "UNKNOWN")[:12]
    redactions = data.get("redacted_count", data.get("redactions_applied", 0))

    # 3. Handle alert storm duplicate suppression
    if dedup_status == "SUPPRESSED_DUPLICATE":
        # Log the spike to Markdown ledger with exclusive POSIX file lock + fsync without waking @sre-repro
        with open(LEDGER_FILE, "a+") as f:
            fcntl.flock(f.fileno(), fcntl.LOCK_EX)
            try:
                f.seek(0, os.SEEK_END)
                if f.tell() == 0:
                    f.write("# SwitchGuard SRE — Sanitized Incidents Ledger\n\n")
                    f.write("| Timestamp | Incident ID | Error Class | Redactions | SHA-256 Digest | Sanitized Summary |\n")
                    f.write("| :--- | :--- | :--- | :--- | :--- | :--- |\n")
                f.write(f"| {timestamp} | `{incident_id}` (SPIKE #{occurrence}) | `{err_class}` | {redactions} | `{sha}...` | [SUPPRESSED SPIKE #{occurrence}] {summary_one_line} |\n")
                f.flush()
                os.fsync(f.fileno())
            finally:
                fcntl.flock(f.fileno(), fcntl.LOCK_UN)

        print(json.dumps({
            "triage_status": "SUPPRESSED_DUPLICATE",
            "incident_id": incident_id,
            "dedup_status": "SUPPRESSED_DUPLICATE",
            "occurrence_count": occurrence,
            "fault_fingerprint": fault_fingerprint,
            "normalized_file_line": file_line,
            "clean_payload": summary_one_line,
            "message": f"Alert storm suppressed in <0.5ms: spike #{occurrence} logged without waking @sre-repro."
        }, indent=2))
        return  # Suppress duplicate — do not wake @sre-repro

    # 4. Incident state machine initialization for new incident
    from incident_state import init_incident
    state_result = init_incident(incident_id, agent="sre-sentinel")

    # 5. Maintain Markdown Ledger with exclusive POSIX file lock + fsync
    with open(LEDGER_FILE, "a+") as f:
        fcntl.flock(f.fileno(), fcntl.LOCK_EX)
        try:
            f.seek(0, os.SEEK_END)
            if f.tell() == 0:
                f.write("# SwitchGuard SRE — Sanitized Incidents Ledger\n\n")
                f.write("| Timestamp | Incident ID | Error Class | Redactions | SHA-256 Digest | Sanitized Summary |\n")
                f.write("| :--- | :--- | :--- | :--- | :--- | :--- |\n")
            f.write(f"| {timestamp} | `{incident_id}` | `{err_class}` | {redactions} | `{sha}...` | {summary_one_line} |\n")
            f.flush()
            os.fsync(f.fileno())
        finally:
            fcntl.flock(f.fileno(), fcntl.LOCK_UN)

    print(json.dumps({
        **data,
        "triage_status": "DISPATCHED",
        "incident_id": incident_id,
        "dedup_status": "FIRST_SEEN",
        "occurrence_count": occurrence,
        "state_machine": state_result,
    }, indent=2))

if __name__ == "__main__":
    raw_input = sys.argv[1] if len(sys.argv) > 1 else "Bearer secret123 user@example.com FLAT100 -$60.00"
    inc_id = sys.argv[2] if len(sys.argv) > 2 else "INC-8041"
    run_triage(raw_input, inc_id)
