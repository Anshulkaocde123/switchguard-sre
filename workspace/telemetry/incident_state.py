#!/usr/bin/env python3
"""
SwitchGuard SRE — Incident State Machine & Circuit Breaker

Enforces a strict one-way DAG: sre-sentinel → sre-repro → Human Commander → sre-clerk
Prevents infinite agent ping-pong loops and deadlocks.

States: TRIAGED → REPRODUCING → PATCH_VERIFIED → RELEASED | ESCALATED
"""

import json
import os
import datetime
import hashlib
from typing import Optional

STATE_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "incident_state.json")

# Valid state transitions (one-way DAG)
VALID_TRANSITIONS = {
    "TRIAGED":        ["REPRODUCING", "ESCALATED", "ROLLED_BACK"],
    "SANITIZED":      ["REPRODUCING", "ESCALATED", "ROLLED_BACK"],
    "REPRODUCING":    ["PATCH_VERIFIED", "ESCALATED", "ROLLED_BACK"],
    "PATCH_VERIFIED": ["RELEASED", "ESCALATED", "ROLLED_BACK"],
    "RELEASED":       ["ROLLED_BACK"],  # Can rollback to HEAD
    "ROLLED_BACK":    [],  # Terminal state
    "ESCALATED":      [],  # Terminal state
}

# Which agent is authorized to make which transitions
AGENT_PERMISSIONS = {
    "sre-sentinel": [("TRIAGED", "REPRODUCING"), ("SANITIZED", "REPRODUCING")],
    "sre-repro":    [("REPRODUCING", "PATCH_VERIFIED"), ("REPRODUCING", "ESCALATED")],
    "commander":    [("PATCH_VERIFIED", "RELEASED"), ("RELEASED", "ROLLED_BACK"), ("PATCH_VERIFIED", "ROLLED_BACK"), ("REPRODUCING", "ROLLED_BACK")],
    "sre-clerk":    [("PATCH_VERIFIED", "RELEASED"), ("RELEASED", "ROLLED_BACK")],
}

MAX_ATTEMPTS = 2  # Circuit breaker threshold


def _load_state() -> dict:
    """Load incident state from persistent JSON file."""
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE, "r") as f:
                data = json.load(f)
                if isinstance(data, dict):
                    if "incidents" not in data:
                        data["incidents"] = {}
                    return data
        except Exception:
            pass
    return {"incidents": {}}


def _save_state(state: dict):
    """Persist incident state atomically, maintaining top-level and per-incident keys."""
    # Ensure top-level tracking fields for the latest incident
    if "incidents" in state and isinstance(state["incidents"], dict) and state["incidents"]:
        latest_id = list(state["incidents"].keys())[-1]
        latest_entry = state["incidents"][latest_id]
        state.setdefault("incident_id", latest_id)
        state["current_state"] = latest_entry.get("current_state", state.get("current_state", "SANITIZED"))
        state["updated_at"] = latest_entry.get("updated_at", state.get("updated_at", ""))
        state.setdefault("retry_count", 0)

    tmp_path = STATE_FILE + ".tmp"
    with open(tmp_path, "w") as f:
        json.dump(state, f, indent=2)
    os.replace(tmp_path, STATE_FILE)


def init_incident(incident_id: str, agent: str = "sre-sentinel") -> dict:
    """Initialize a new incident in TRIAGED state."""
    state = _load_state()
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()

    if incident_id in state["incidents"]:
        existing = state["incidents"][incident_id]
        return {
            "status": "ALREADY_EXISTS",
            "incident_id": incident_id,
            "current_state": existing["current_state"],
            "message": f"Incident {incident_id} already exists in state {existing['current_state']}"
        }

    state["incidents"][incident_id] = {
        "current_state": "TRIAGED",
        "created_at": now,
        "updated_at": now,
        "attempt_counts": {
            "reproduce": 0,
            "verify": 0,
            "pytest": 0,
        },
        "history": [
            {
                "from_state": None,
                "to_state": "TRIAGED",
                "agent": agent,
                "timestamp": now,
                "message": "Incident created and triaged"
            }
        ],
        "circuit_breaker_tripped": False,
    }

    _save_state(state)
    return {
        "status": "CREATED",
        "incident_id": incident_id,
        "current_state": "TRIAGED",
        "timestamp": now,
    }


def transition(incident_id: str, to_state: str, agent: str, message: str = "") -> dict:
    """
    Attempt a state transition. Enforces:
    1. Valid state transitions (one-way DAG)
    2. Agent authorization
    3. Circuit breaker (MAX_ATTEMPTS)
    """
    state = _load_state()
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()

    if incident_id not in state["incidents"]:
        return {
            "status": "ERROR",
            "error": f"Incident {incident_id} not found. Call init_incident first.",
        }

    incident = state["incidents"][incident_id]
    current = incident["current_state"]

    # Check terminal state
    if current in ("RELEASED", "ESCALATED"):
        return {
            "status": "REJECTED",
            "error": f"Incident {incident_id} is in terminal state {current}. No further transitions allowed.",
            "current_state": current,
        }

    # Check circuit breaker
    if incident.get("circuit_breaker_tripped"):
        return {
            "status": "CIRCUIT_BREAKER_TRIPPED",
            "error": f"[CIRCUIT_BREAKER_TRIPPED] Incident {incident_id} has exceeded MAX_ATTEMPTS={MAX_ATTEMPTS}. Escalating to @admin.",
            "current_state": current,
        }

    # Validate transition
    if to_state not in VALID_TRANSITIONS.get(current, []):
        return {
            "status": "INVALID_TRANSITION",
            "error": f"Cannot transition from {current} → {to_state}. Valid targets: {VALID_TRANSITIONS.get(current, [])}",
            "current_state": current,
        }

    # Validate agent authorization
    allowed = AGENT_PERMISSIONS.get(agent, [])
    if (current, to_state) not in allowed:
        return {
            "status": "UNAUTHORIZED",
            "error": f"Agent '{agent}' is not authorized for transition {current} → {to_state}.",
            "current_state": current,
        }

    # Execute transition
    incident["current_state"] = to_state
    incident["updated_at"] = now
    incident["history"].append({
        "from_state": current,
        "to_state": to_state,
        "agent": agent,
        "timestamp": now,
        "message": message,
    })

    _save_state(state)
    return {
        "status": "TRANSITIONED",
        "incident_id": incident_id,
        "from_state": current,
        "to_state": to_state,
        "agent": agent,
        "timestamp": now,
    }


def record_attempt(incident_id: str, attempt_type: str) -> dict:
    """
    Record an attempt (reproduce, verify, pytest) and check circuit breaker.
    If MAX_ATTEMPTS is exceeded, trips the breaker and forces ESCALATED state.
    """
    state = _load_state()
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()

    if incident_id not in state["incidents"]:
        return {"status": "ERROR", "error": f"Incident {incident_id} not found."}

    incident = state["incidents"][incident_id]

    if attempt_type not in incident["attempt_counts"]:
        incident["attempt_counts"][attempt_type] = 0

    incident["attempt_counts"][attempt_type] += 1
    count = incident["attempt_counts"][attempt_type]

    if count >= MAX_ATTEMPTS:
        incident["circuit_breaker_tripped"] = True
        incident["current_state"] = "ESCALATED"
        incident["updated_at"] = now
        incident["history"].append({
            "from_state": incident["current_state"],
            "to_state": "ESCALATED",
            "agent": "circuit_breaker",
            "timestamp": now,
            "message": f"[CIRCUIT_BREAKER_TRIPPED] {attempt_type} failed {count} times (max={MAX_ATTEMPTS}). Escalating to @admin.",
        })
        _save_state(state)
        return {
            "status": "CIRCUIT_BREAKER_TRIPPED",
            "incident_id": incident_id,
            "attempt_type": attempt_type,
            "attempt_count": count,
            "max_attempts": MAX_ATTEMPTS,
            "message": f"[CIRCUIT_BREAKER_TRIPPED] Escalating to @admin after {count} failed {attempt_type} attempts.",
        }

    _save_state(state)
    return {
        "status": "ATTEMPT_RECORDED",
        "incident_id": incident_id,
        "attempt_type": attempt_type,
        "attempt_count": count,
        "remaining": MAX_ATTEMPTS - count,
    }


def get_state(incident_id: str) -> dict:
    """Get the current state of an incident."""
    state = _load_state()
    if incident_id not in state["incidents"]:
        return {"status": "NOT_FOUND", "incident_id": incident_id}
    incident = state["incidents"][incident_id]
    return {
        "status": "OK",
        "incident_id": incident_id,
        "current_state": incident["current_state"],
        "circuit_breaker_tripped": incident.get("circuit_breaker_tripped", False),
        "attempt_counts": incident["attempt_counts"],
        "history_length": len(incident["history"]),
        "created_at": incident["created_at"],
        "updated_at": incident["updated_at"],
    }


def get_all_incidents() -> dict:
    """Get summary of all tracked incidents."""
    state = _load_state()
    summary = {}
    for iid, data in state["incidents"].items():
        summary[iid] = {
            "current_state": data["current_state"],
            "circuit_breaker_tripped": data.get("circuit_breaker_tripped", False),
            "updated_at": data["updated_at"],
        }
    return {"status": "OK", "incidents": summary, "total": len(summary)}


if __name__ == "__main__":
    import sys

    if len(sys.argv) < 2:
        print("Usage: incident_state.py <init|transition|attempt|status|list> [args...]")
        sys.exit(1)

    cmd = sys.argv[1]
    if cmd == "init":
        inc_id = sys.argv[2] if len(sys.argv) > 2 else "INC-0001"
        print(json.dumps(init_incident(inc_id), indent=2))
    elif cmd == "transition":
        inc_id = sys.argv[2]
        to_state = sys.argv[3]
        agent = sys.argv[4]
        msg = sys.argv[5] if len(sys.argv) > 5 else ""
        print(json.dumps(transition(inc_id, to_state, agent, msg), indent=2))
    elif cmd == "attempt":
        inc_id = sys.argv[2]
        attempt_type = sys.argv[3]
        print(json.dumps(record_attempt(inc_id, attempt_type), indent=2))
    elif cmd == "status":
        inc_id = sys.argv[2]
        print(json.dumps(get_state(inc_id), indent=2))
    elif cmd == "list":
        print(json.dumps(get_all_incidents(), indent=2))
    else:
        print(f"Unknown command: {cmd}")
        sys.exit(1)
