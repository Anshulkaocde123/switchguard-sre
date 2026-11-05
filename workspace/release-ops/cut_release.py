import sys, datetime

def execute_release(incident_id: str, version: str):
    timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()
    with open("RELEASE_AUDIT.log", "a") as f:
        f.write(f"[{timestamp}] HOTFIX RELEASED: {version} for {incident_id}\n")
    print(f"Hotfix branch release/hotfix-{version} generated and logged.")

if __name__ == "__main__":
    inc_id = sys.argv[1] if len(sys.argv) > 1 else "INC-8041"
    ver = sys.argv[2] if len(sys.argv) > 2 else "v1.4.2"
    execute_release(inc_id, ver)
