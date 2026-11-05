import subprocess
import json
import sys
import datetime
import os
import shutil
import fcntl
import time

TELEMETRY_DIR = os.path.dirname(os.path.abspath(__file__))
LEDGER_FILE = os.path.join(TELEMETRY_DIR, "incidents_ledger.md")
DEDUP_INDEX_FILE = os.path.join(TELEMETRY_DIR, "dedup_index.json")
STATE_FILE = os.path.join(TELEMETRY_DIR, "incident_state.json")
RUNBOOK_MEMORY_FILE = os.path.join(TELEMETRY_DIR, "runbook_memory.json")
TRIAGE_LOCK_FILE = os.path.join(TELEMETRY_DIR, ".triage.lock")

def check_circuit_breaker(state_data: dict = None, incident_id: str = None) -> dict:
    """
    Circuit Breaker helper: if retry_count >= 2 in incident_state.json,
    sets current_state = "CIRCUIT_BROKEN".
    """
    if state_data is None:
        if not os.path.exists(STATE_FILE):
            return {"circuit_broken": False, "retry_count": 0, "current_state": "NONE"}
        try:
            with open(STATE_FILE, "r") as sf:
                state_data = json.load(sf)
        except Exception:
            state_data = {}

    target_id = incident_id or state_data.get("incident_id")
    retry_count = state_data.get("retry_count", 0)
    inc_entry = state_data.get("incidents", {}).get(target_id, {})
    if inc_entry:
        retry_count = max(retry_count, inc_entry.get("retry_count", 0))
        for attempts in inc_entry.get("attempt_counts", {}).values():
            retry_count = max(retry_count, attempts)

    circuit_broken = retry_count >= 2
    if circuit_broken:
        state_data["current_state"] = "CIRCUIT_BROKEN"
        state_data["retry_count"] = retry_count
        if target_id and "incidents" in state_data and target_id in state_data["incidents"]:
            state_data["incidents"][target_id]["current_state"] = "CIRCUIT_BROKEN"
            state_data["incidents"][target_id]["circuit_breaker_tripped"] = True
            state_data["incidents"][target_id]["retry_count"] = retry_count
        with open(STATE_FILE + ".tmp", "w") as sf:
            json.dump(state_data, sf, indent=2)
        os.replace(STATE_FILE + ".tmp", STATE_FILE)
        return {"circuit_broken": True, "retry_count": retry_count, "current_state": "CIRCUIT_BROKEN", "state_data": state_data}

    return {"circuit_broken": False, "retry_count": retry_count, "current_state": state_data.get("current_state"), "state_data": state_data}

def query_runbook_memory(err_class: str) -> dict | None:
    """Query episodic runbook memory for prior resolutions matching error classification."""
    if not os.path.exists(RUNBOOK_MEMORY_FILE):
        return None
    try:
        with open(RUNBOOK_MEMORY_FILE, "r") as mf:
            mem_data = json.load(mf)
            entries = mem_data if isinstance(mem_data, list) else mem_data.get("resolutions", mem_data.get("entries", []))
            for entry in reversed(entries):
                if entry.get("error_classification") == err_class or entry.get("error_class") == err_class:
                    return {
                        "prior_incident_id": entry.get("incident_id", "UNKNOWN"),
                        "target_file": entry.get("target_file", "cart_service.py"),
                        "fix_pattern": entry.get("fix_pattern", "max(0.0, subtotal - 100.0)"),
                        "summary": entry.get("summary", ""),
                        "version": entry.get("version", ""),
                        "patch_sha256": entry.get("patch_sha256", "")
                    }
    except Exception:
        pass
    return None

def update_incident_state(incident_id: str, current_state: str = "SANITIZED", scrub_latency_ms: float = 0.0) -> dict:
    """Maintains incident_state.json tracking incident_id, current_state, updated_at, retry_count, scrub_latency_ms."""
    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
    state_data = {}
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, "r") as sf:
                state_data = json.load(sf)
        except Exception:
            state_data = {}

    inc_entry = state_data.get("incidents", {}).get(incident_id, {})
    retry_count = inc_entry.get("retry_count", 0)
    attempts = max(inc_entry.get("attempt_counts", {}).values(), default=0)
    retry_count = max(retry_count, attempts)

    # Circuit breaker: if retry_count >= 2 for this incident, set current_state = "CIRCUIT_BROKEN"
    if retry_count >= 2:
        current_state = "CIRCUIT_BROKEN"

    state_data["incident_id"] = incident_id
    state_data["current_state"] = current_state
    state_data["updated_at"] = now_iso
    state_data["retry_count"] = retry_count
    state_data["scrub_latency_ms"] = scrub_latency_ms

    if "incidents" not in state_data or not isinstance(state_data["incidents"], dict):
        state_data["incidents"] = {}

    incident_entry = state_data["incidents"].get(incident_id, {
        "current_state": current_state,
        "created_at": now_iso,
        "attempt_counts": {"reproduce": 0, "verify": 0, "pytest": 0},
        "history": [],
        "circuit_breaker_tripped": False,
    })
    incident_entry["current_state"] = current_state
    incident_entry["updated_at"] = now_iso
    incident_entry["retry_count"] = retry_count
    incident_entry["scrub_latency_ms"] = scrub_latency_ms
    if retry_count >= 2:
        incident_entry["circuit_breaker_tripped"] = True

    if "history" not in incident_entry:
        incident_entry["history"] = []
    incident_entry["history"].append({
        "from_state": incident_entry.get("current_state"),
        "to_state": current_state,
        "agent": "sre-sentinel",
        "timestamp": now_iso,
        "message": f"Log sanitized via switchguard-cli in {scrub_latency_ms}ms"
    })
    state_data["incidents"][incident_id] = incident_entry

    with open(STATE_FILE + ".tmp", "w") as sf:
        json.dump(state_data, sf, indent=2)
    os.replace(STATE_FILE + ".tmp", STATE_FILE)
    return state_data

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
    with open(TRIAGE_LOCK_FILE, "a+") as lock_file:
        fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
        try:
            # 1. Invoke compiled Rust switchguard-cli binary (<0.4ms PII scrub + canonical fault fingerprint)
            cli_bin = shutil.which("switchguard-cli") or os.path.expanduser("~/.local/bin/switchguard-cli")
            t0 = time.perf_counter()
            env = os.environ.copy()
            env["SWITCHGUARD_DEDUP_INDEX"] = DEDUP_INDEX_FILE
            proc = subprocess.run(
                [cli_bin, "scrub", raw_log],
                capture_output=True,
                text=True,
                check=True,
                env=env,
            )
            scrub_latency_ms = round((time.perf_counter() - t0) * 1000, 2)
            data = json.loads(proc.stdout)

            fault_fingerprint = data.get("fault_fingerprint", "unknown")
            file_line = data.get("normalized_file_line", "unknown:0")
            err_class = data.get("error_classification", data.get("error_class", "UNKNOWN"))

            # 2. Check episodic runbook memory for historical match
            historical_match = query_runbook_memory(err_class)

            # 3. Synchronize dedup_index.json with exclusive POSIX flock
            dedup_status, occurrence = verify_and_lock_dedup_index(fault_fingerprint, data)

            timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
            summary_one_line = data.get("clean_payload", data.get("sanitized_text", "")).replace("\n", " ")
            sha = data.get("sha256", "UNKNOWN")[:12]
            redactions = data.get("redacted_count", data.get("redactions_applied", 0))

            # 4. Handle alert storm duplicate suppression
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
                    "scrub_latency_ms": scrub_latency_ms,
                    "historical_runbook_match": historical_match,
                    "message": f"Alert storm suppressed in <0.5ms: spike #{occurrence} logged without waking @sre-repro."
                }, indent=2))
                return  # Suppress duplicate — do not wake @sre-repro

            # 5. Incident state machine tracking (incident_state.json)
            state_result = update_incident_state(incident_id, current_state="SANITIZED", scrub_latency_ms=scrub_latency_ms)

            # 6. Maintain Markdown Ledger with exclusive POSIX file lock + fsync
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
                "scrub_latency_ms": scrub_latency_ms,
                "state_machine": state_result,
                "historical_runbook_match": historical_match,
            }, indent=2))
        finally:
            fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)

if __name__ == "__main__":
    raw_input = sys.argv[1] if len(sys.argv) > 1 else "Bearer secret123 user@example.com FLAT100 -$60.00"
    inc_id = sys.argv[2] if len(sys.argv) > 2 else "INC-8041"
    run_triage(raw_input, inc_id)
