import re, json, sys

def sanitize_and_classify(raw_log: str) -> dict:
    clean_log = re.sub(r'(Bearer\s+[A-Za-z0-9_\-\.]+)', '[REDACTED_AUTH_TOKEN]', raw_log)
    clean_log = re.sub(r'([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)', '[REDACTED_EMAIL]', clean_log)
    
    error_type = "NEGATIVE_TOTAL_CALCULATION" if ("AssertionError" in clean_log or "FLAT100" in clean_log) else "UNKNOWN"
    return {"status": "SANITIZED", "error_class": error_type, "clean_payload": clean_log}

if __name__ == "__main__":
    input_data = sys.argv[1] if len(sys.argv) > 1 else ""
    print(json.dumps(sanitize_and_classify(input_data), indent=2))
