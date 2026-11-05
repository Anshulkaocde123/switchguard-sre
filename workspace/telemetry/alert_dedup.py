#!/usr/bin/env python3
"""
SwitchGuard SRE — Alert-Storm Deduplication

Prevents duplicate incidents from flooding the pipeline when the same root cause
fires multiple alerts. Uses content-based hashing with a configurable time window.
"""

import json
import os
import datetime
import hashlib
from typing import Optional

DEDUP_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "alert_dedup_cache.json")

# Dedup window in seconds (5 minutes default)
DEDUP_WINDOW_SECONDS = 300

# Fields to use for fingerprinting
FINGERPRINT_FIELDS = ["error_classification", "component", "discount_code"]


def _load_cache() -> dict:
    """Load dedup cache from disk."""
    if os.path.exists(DEDUP_FILE):
        with open(DEDUP_FILE, "r") as f:
            return json.load(f)
    return {"alerts": {}}


def _save_cache(cache: dict):
    """Persist dedup cache atomically."""
    tmp_path = DEDUP_FILE + ".tmp"
    with open(tmp_path, "w") as f:
        json.dump(cache, f, indent=2)
    os.replace(tmp_path, DEDUP_FILE)


def _compute_fingerprint(alert_data: dict) -> str:
    """
    Compute a content-based fingerprint from alert fields.
    Falls back to full content hash if fingerprint fields are missing.
    """
    parts = []
    for field in FINGERPRINT_FIELDS:
        if field in alert_data:
            parts.append(f"{field}={alert_data[field]}")

    if not parts:
        # Fallback: hash the full sanitized text
        content = alert_data.get("sanitized_text", alert_data.get("clean_payload", str(alert_data)))
        return hashlib.sha256(content.encode()).hexdigest()[:16]

    fingerprint_str = "|".join(sorted(parts))
    return hashlib.sha256(fingerprint_str.encode()).hexdigest()[:16]


def check_and_register(alert_data: dict, incident_id: str = None) -> dict:
    """
    Check if an alert is a duplicate within the dedup window.

    Returns:
        - status: "NEW" if first occurrence, "DUPLICATE" if within window, "EXPIRED_REOPEN" if past window
        - fingerprint: the computed content hash
        - suppressed_count: how many duplicates were suppressed
    """
    cache = _load_cache()
    now = datetime.datetime.now(datetime.timezone.utc)
    now_iso = now.isoformat()
    fingerprint = _compute_fingerprint(alert_data)

    # Purge expired entries
    expired_keys = []
    for fp, entry in cache["alerts"].items():
        last_seen = datetime.datetime.fromisoformat(entry["last_seen"])
        if (now - last_seen).total_seconds() > DEDUP_WINDOW_SECONDS * 10:
            expired_keys.append(fp)
    for key in expired_keys:
        del cache["alerts"][key]

    if fingerprint in cache["alerts"]:
        entry = cache["alerts"][fingerprint]
        last_seen = datetime.datetime.fromisoformat(entry["last_seen"])
        elapsed = (now - last_seen).total_seconds()

        if elapsed <= DEDUP_WINDOW_SECONDS:
            # Duplicate within window — suppress
            entry["suppressed_count"] += 1
            entry["last_seen"] = now_iso
            _save_cache(cache)
            return {
                "status": "DUPLICATE",
                "fingerprint": fingerprint,
                "original_incident_id": entry["incident_id"],
                "suppressed_count": entry["suppressed_count"],
                "first_seen": entry["first_seen"],
                "last_seen": now_iso,
                "window_remaining_seconds": int(DEDUP_WINDOW_SECONDS - elapsed),
                "message": f"Alert suppressed — duplicate of {entry['incident_id']} (seen {entry['suppressed_count']} times in window)",
            }
        else:
            # Past window — allow as new but note re-open
            old_id = entry["incident_id"]
            entry["incident_id"] = incident_id or entry["incident_id"]
            entry["suppressed_count"] = 0
            entry["first_seen"] = now_iso
            entry["last_seen"] = now_iso
            _save_cache(cache)
            return {
                "status": "EXPIRED_REOPEN",
                "fingerprint": fingerprint,
                "previous_incident_id": old_id,
                "new_incident_id": incident_id,
                "message": f"Alert window expired ({int(elapsed)}s > {DEDUP_WINDOW_SECONDS}s). Reopening as new incident.",
            }
    else:
        # New alert
        cache["alerts"][fingerprint] = {
            "incident_id": incident_id or f"INC-{fingerprint[:6].upper()}",
            "fingerprint": fingerprint,
            "first_seen": now_iso,
            "last_seen": now_iso,
            "suppressed_count": 0,
            "sample_data": {
                k: alert_data.get(k, "") for k in FINGERPRINT_FIELDS
            },
        }
        _save_cache(cache)
        return {
            "status": "NEW",
            "fingerprint": fingerprint,
            "incident_id": cache["alerts"][fingerprint]["incident_id"],
            "message": "New alert fingerprint registered.",
        }


def get_stats() -> dict:
    """Return dedup statistics."""
    cache = _load_cache()
    total_suppressed = sum(e["suppressed_count"] for e in cache["alerts"].values())
    return {
        "status": "OK",
        "unique_fingerprints": len(cache["alerts"]),
        "total_suppressed": total_suppressed,
        "dedup_window_seconds": DEDUP_WINDOW_SECONDS,
    }


def clear_cache():
    """Clear the dedup cache."""
    _save_cache({"alerts": {}})
    return {"status": "CLEARED"}


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: alert_dedup.py <check|stats|clear> [json_data] [incident_id]")
        sys.exit(1)

    cmd = sys.argv[1]
    if cmd == "check":
        data = json.loads(sys.argv[2]) if len(sys.argv) > 2 else {"error_classification": "NEGATIVE_TOTAL_CALCULATION", "component": "cart_service.py"}
        inc_id = sys.argv[3] if len(sys.argv) > 3 else None
        print(json.dumps(check_and_register(data, inc_id), indent=2))
    elif cmd == "stats":
        print(json.dumps(get_stats(), indent=2))
    elif cmd == "clear":
        print(json.dumps(clear_cache(), indent=2))
    else:
        print(f"Unknown command: {cmd}")
        sys.exit(1)
