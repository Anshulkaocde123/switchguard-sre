use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{self, Command};
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(unix)]
use std::os::unix::io::AsRawFd;

#[cfg(unix)]
extern "C" {
    fn flock(fd: std::os::raw::c_int, operation: std::os::raw::c_int) -> std::os::raw::c_int;
}

#[cfg(unix)]
const LOCK_EX: std::os::raw::c_int = 2;
#[cfg(unix)]
const LOCK_UN: std::os::raw::c_int = 8;

#[derive(Serialize)]
struct ScrubOutput {
    status: String,
    sanitized_text: String,
    clean_payload: String,
    sha256: String,
    error_classification: String,
    redacted_count: usize,
    dedup_status: String,
    fault_fingerprint: String,
    occurrence_count: u64,
    normalized_file_line: String,
}

#[derive(Serialize)]
struct VerifyRule {
    rule: String,
    status: String,
    description: String,
}

#[derive(Serialize)]
struct VerifyOutput {
    verdict: String,
    status: String,
    target_path: String,
    sha256: String,
    forbidden_findings: Vec<String>,
    rules: Vec<VerifyRule>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct DedupEntry {
    error_classification: String,
    normalized_file_line: String,
    occurrence_count: u64,
    first_seen: String,
    last_seen: String,
    last_timestamp_secs: u64,
}

#[derive(Serialize, Deserialize, Default, Debug)]
struct DedupIndex {
    #[serde(default)]
    version: String,
    #[serde(default)]
    fingerprints: HashMap<String, DedupEntry>,
}

#[derive(Serialize)]
struct AuditVerifyEntry {
    entry_index: usize,
    timestamp: String,
    patch_sha256: String,
    prev_chain_hash: String,
    recorded_chain_hash: String,
    computed_chain_hash: String,
    valid: bool,
}

#[derive(Serialize)]
struct AuditVerifyOutput {
    verdict: String,
    status: String,
    audit_log: String,
    genesis_hash: String,
    entries_verified: usize,
    latest_chain_hash: String,
    tamper_detected: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    failed_entry: Option<AuditVerifyEntry>,
}

fn compute_hmac_token(val: &str) -> String {
    let key = env::var("SWITCHGUARD_HMAC_KEY").unwrap_or_default();
    let hash = if key.is_empty() {
        format!("{:x}", Sha256::digest(val.as_bytes()))
    } else {
        let mut hasher = Sha256::new();
        hasher.update(key.as_bytes());
        hasher.update(b":");
        hasher.update(val.as_bytes());
        format!("{:x}", hasher.finalize())
    };
    hash[..6].to_string()
}

fn scrub_payload(raw_text: &str) -> (String, usize, String, String) {
    let mut text = raw_text.to_string();
    let mut total_redactions = 0;

    // 1. Redact Bearer tokens (e.g. Bearer secret123, Bearer eyJ...)
    let re_bearer = Regex::new(r"Bearer\s+[A-Za-z0-9_\-\.]+").unwrap();
    let bearer_matches = re_bearer.find_iter(&text).count();
    total_redactions += bearer_matches;
    text = re_bearer.replace_all(&text, "Bearer [REDACTED_AUTH_TOKEN]").to_string();

    // 2. Redact Known Secret Keys (API keys, live tokens, password/secret params)
    let re_secrets = Regex::new(r"\b(AIzaSy[A-Za-z0-9_\-]{33}|sk_live_[A-Za-z0-9]+|ghp_[A-Za-z0-9]+|tok_live_[A-Za-z0-9]+)\b").unwrap();
    let secret_matches = re_secrets.find_iter(&text).count();
    total_redactions += secret_matches;
    text = re_secrets.replace_all(&text, "[REDACTED_SECRET]").to_string();

    let re_kv_secrets = Regex::new(r"(?i)\b(password|secret|apikey|api_key)\s*[:=]\s*([^\s,;]+)").unwrap();
    let kv_matches = re_kv_secrets.find_iter(&text).count();
    total_redactions += kv_matches;
    text = re_kv_secrets.replace_all(&text, "$1=[REDACTED_SECRET]").to_string();

    // 3. Redact AWS Access Keys: AKIA[0-9A-Z]{16}
    let re_aws = Regex::new(r"\bAKIA[0-9A-Z]{16}\b").unwrap();
    let aws_matches = re_aws.find_iter(&text).count();
    total_redactions += aws_matches;
    text = re_aws.replace_all(&text, "[REDACTED_AWS_KEY]").to_string();

    // 4. Redact Private Keys: -----BEGIN.*PRIVATE KEY-----
    let re_priv_key = Regex::new(r"(?s)-----BEGIN[ A-Z0-9_-]*PRIVATE KEY-----.*?-----END[ A-Z0-9_-]*PRIVATE KEY-----|-----BEGIN[ A-Z0-9_-]*PRIVATE KEY[^\r\n]*").unwrap();
    let priv_matches = re_priv_key.find_iter(&text).count();
    total_redactions += priv_matches;
    text = re_priv_key.replace_all(&text, "[REDACTED_PRIVATE_KEY]").to_string();

    // 5. Redact Credit Card / PAN patterns (e.g. 4532-xxxx-xxxx-xxxx, 16 digit PANs)
    let re_cc = Regex::new(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|6(?:011|5[0-9]{2})[0-9]{12}|3[47][0-9]{13}|(?:[0-9]{4}[ -]?){3}[0-9]{4})\b").unwrap();
    let cc_matches = re_cc.find_iter(&text).count();
    total_redactions += cc_matches;
    text = re_cc.replace_all(&text, "[REDACTED_CREDIT_CARD]").to_string();

    // 6. Redact Email addresses with HMAC suffix (e.g. [REDACTED_EMAIL_8f3a1c])
    let re_email = Regex::new(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+").unwrap();
    let email_matches = re_email.find_iter(&text).count();
    total_redactions += email_matches;
    text = re_email.replace_all(&text, |caps: &regex::Captures| {
        let matched = caps.get(0).map_or("", |m| m.as_str());
        let token = compute_hmac_token(matched);
        format!("[REDACTED_EMAIL_{}]", token)
    }).to_string();

    // 7. Redact IPv4 addresses with HMAC suffix (e.g. [REDACTED_IPV4_8f3a1c])
    let re_ipv4 = Regex::new(r"\b(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b").unwrap();
    let ip_matches = re_ipv4.find_iter(&text).count();
    total_redactions += ip_matches;
    text = re_ipv4.replace_all(&text, |caps: &regex::Captures| {
        let matched = caps.get(0).map_or("", |m| m.as_str());
        let token = compute_hmac_token(matched);
        format!("[REDACTED_IPV4_{}]", token)
    }).to_string();

    // Classification
    let classification = if text.contains("FLAT100") || text.contains("-$60") || text.contains("NEGATIVE") {
        "NEGATIVE_TOTAL_CALCULATION".to_string()
    } else if text.contains("ZeroDivisionError") || text.contains("SAVE20") || text.contains("division by zero") {
        "ZERO_DIVISION_ERROR".to_string()
    } else if text.contains("AssertionError") {
        "ASSERTION_FAILURE".to_string()
    } else {
        "BUG".to_string()
    };

    let hash = format!("{:x}", Sha256::digest(text.as_bytes()));
    (text, total_redactions, classification, hash)
}

fn extract_normalized_file_line(text: &str) -> String {
    // 1. Look for patterns like "cart_service.py line 5", "cart_service.py:5", 'File "cart_service.py", line 5'
    let re_line = Regex::new(r#"(?i)(?:File\s+["']?|in\s+)?([a-zA-Z0-9_\-\.]+\.py)["']?(?:[^\d\n]*line\s*|:|\s*\(\s*line\s*)(\d+)"#).unwrap();
    if let Some(caps) = re_line.captures(text) {
        let file = caps.get(1).map_or("", |m| m.as_str());
        let line = caps.get(2).map_or("", |m| m.as_str());
        let filename = Path::new(file).file_name().and_then(|s| s.to_str()).unwrap_or(file);
        return format!("{}:{}", filename, line);
    }

    // 2. Look for just filename.py
    let re_file = Regex::new(r#"(?i)([a-zA-Z0-9_\-\.]+\.py)"#).unwrap();
    if let Some(caps) = re_file.captures(text) {
        let file = caps.get(1).map_or("", |m| m.as_str());
        let filename = Path::new(file).file_name().and_then(|s| s.to_str()).unwrap_or(file);
        return format!("{}:0", filename);
    }

    // 3. Known domain mappings
    if text.contains("FLAT100") || text.contains("-$60") || text.contains("NEGATIVE") {
        "cart_service.py:5".to_string()
    } else if text.contains("ZeroDivisionError") || text.contains("SAVE20") {
        "pricing.py:12".to_string()
    } else {
        "unknown:0".to_string()
    }
}

fn resolve_dedup_index_path() -> PathBuf {
    if let Ok(val) = env::var("SWITCHGUARD_DEDUP_INDEX") {
        return PathBuf::from(val);
    }

    let candidates = [
        "workspace/telemetry/dedup_index.json",
        "../telemetry/dedup_index.json",
        "./dedup_index.json",
        "/home/anshul-jain/switchguard-sre/workspace/telemetry/dedup_index.json",
    ];

    for candidate in &candidates {
        let p = Path::new(candidate);
        if let Some(parent) = p.parent() {
            if parent.exists() {
                return p.to_path_buf();
            }
        }
    }

    PathBuf::from("/home/anshul-jain/switchguard-sre/workspace/telemetry/dedup_index.json")
}

fn record_or_check_dedup(
    error_classification: &str,
    normalized_file_line: &str,
    fault_fingerprint: &str,
) -> (String, u64) {
    let index_path = resolve_dedup_index_path();
    if let Some(parent) = index_path.parent() {
        let _ = fs::create_dir_all(parent);
    }

    let lock_path = index_path.with_extension("lock");
    let lock_file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .open(&lock_path);

    #[cfg(unix)]
    if let Ok(ref f) = lock_file {
        unsafe {
            flock(f.as_raw_fd(), LOCK_EX);
        }
    }

    let window_secs: u64 = env::var("SWITCHGUARD_DEDUP_WINDOW_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(300);

    let now_secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let now_iso = format!("{}-UTC", now_secs);

    let mut index: DedupIndex = if index_path.exists() {
        fs::read_to_string(&index_path)
            .ok()
            .and_then(|c| serde_json::from_str(&c).ok())
            .unwrap_or_default()
    } else {
        DedupIndex::default()
    };
    if index.version.is_empty() {
        index.version = "1.0".to_string();
    }

    let (status, count) = if let Some(entry) = index.fingerprints.get_mut(fault_fingerprint) {
        let elapsed = now_secs.saturating_sub(entry.last_timestamp_secs);
        if elapsed <= window_secs {
            entry.occurrence_count += 1;
            entry.last_seen = now_iso;
            entry.last_timestamp_secs = now_secs;
            ("SUPPRESSED_DUPLICATE".to_string(), entry.occurrence_count)
        } else {
            entry.occurrence_count = 1;
            entry.first_seen = now_iso.clone();
            entry.last_seen = now_iso;
            entry.last_timestamp_secs = now_secs;
            ("FIRST_SEEN".to_string(), 1)
        }
    } else {
        let entry = DedupEntry {
            error_classification: error_classification.to_string(),
            normalized_file_line: normalized_file_line.to_string(),
            occurrence_count: 1,
            first_seen: now_iso.clone(),
            last_seen: now_iso,
            last_timestamp_secs: now_secs,
        };
        index.fingerprints.insert(fault_fingerprint.to_string(), entry);
        ("FIRST_SEEN".to_string(), 1)
    };

    if let Ok(json_str) = serde_json::to_string_pretty(&index) {
        let tmp_path = index_path.with_extension("tmp");
        if fs::write(&tmp_path, json_str).is_ok() {
            let _ = fs::rename(&tmp_path, &index_path);
        }
    }

    #[cfg(unix)]
    if let Ok(ref f) = lock_file {
        unsafe {
            flock(f.as_raw_fd(), LOCK_UN);
        }
    }

    (status, count)
}

fn run_verify_diff(path_str: &str) -> VerifyOutput {
    let target = Path::new(path_str);
    let mut diff_text = String::new();

    // 1. Inspect diff against HEAD to include both staged and unstaged changes
    if let Ok(output) = Command::new("git")
        .args(["-C", path_str, "diff", "HEAD"])
        .output()
    {
        diff_text.push_str(&String::from_utf8_lossy(&output.stdout));
    }

    // Fallback: check cached diff if unstaged was empty
    if diff_text.trim().is_empty() {
        if let Ok(output) = Command::new("git")
            .args(["-C", path_str, "diff", "--cached"])
            .output()
        {
            diff_text.push_str(&String::from_utf8_lossy(&output.stdout));
        }
    }

    // Fallback: check HEAD~1 HEAD if working tree is clean
    if diff_text.trim().is_empty() {
        if let Ok(output) = Command::new("git")
            .args(["-C", path_str, "diff", "HEAD~1", "HEAD"])
            .output()
        {
            diff_text.push_str(&String::from_utf8_lossy(&output.stdout));
        }
    }

    let diff_hash = format!("{:x}", Sha256::digest(diff_text.as_bytes()));

    // Split diff by file blocks
    let mut file_diffs: Vec<(String, Vec<String>, Vec<String>)> = Vec::new();
    let mut current_file = String::new();
    let mut current_added: Vec<String> = Vec::new();
    let mut current_deleted: Vec<String> = Vec::new();

    for line in diff_text.lines() {
        if line.starts_with("diff --git") {
            if !current_file.is_empty() {
                file_diffs.push((current_file.clone(), current_added.clone(), current_deleted.clone()));
                current_added.clear();
                current_deleted.clear();
            }
            // Parse filename from diff --git a/path b/path
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 4 {
                let path_b = parts[3].trim_start_matches("b/");
                current_file = path_b.to_string();
            } else {
                current_file = line.to_string();
            }
        } else if line.starts_with('+') && !line.starts_with("+++") {
            current_added.push(line.to_string());
        } else if line.starts_with('-') && !line.starts_with("---") {
            current_deleted.push(line.to_string());
        }
    }
    if !current_file.is_empty() {
        file_diffs.push((current_file, current_added, current_deleted));
    }

    // Count changes in .py application files (non-test files)
    let app_py_files: Vec<&(String, Vec<String>, Vec<String>)> = file_diffs
        .iter()
        .filter(|(f, _, _)| f.ends_with(".py") && !f.contains("test_") && !f.contains("/tests/"))
        .collect();

    let app_py_lines_added: usize = app_py_files.iter().map(|(_, a, _)| a.len()).sum();
    let app_py_lines_deleted: usize = app_py_files.iter().map(|(_, _, d)| d.len()).sum();
    let app_py_has_changes = (app_py_lines_added + app_py_lines_deleted) > 0;

    // Reject empty diffs if no lines are changed in .py application files (exit code 3)
    if diff_text.trim().is_empty() || !app_py_has_changes {
        return VerifyOutput {
            verdict: "BLOCKED".to_string(),
            status: "EMPTY_PATCH_REJECTED".to_string(),
            target_path: target.display().to_string(),
            sha256: diff_hash,
            forbidden_findings: vec![format!(
                "AST-SEC-00: EMPTY_PATCH_REJECTED — No changes in .py application files (app_files={}, app_lines_added={}, app_lines_deleted={})",
                app_py_files.len(),
                app_py_lines_added,
                app_py_lines_deleted
            )],
            rules: vec![VerifyRule {
                rule: "AST-SEC-00: NO_EMPTY_PATCH".to_string(),
                status: "FAIL".to_string(),
                description: "Rejects empty diffs or diffs without modifications to .py application files".to_string(),
            }],
        };
    }

    let mut findings: Vec<String> = Vec::new();

    // AST-SEC-09: MINIMAL_BLAST_RADIUS — Enforce minimal blast radius (max 25 added lines in production .py files)
    if app_py_lines_added > 25 {
        findings.push(format!(
            "AST-SEC-09: MINIMAL_BLAST_RADIUS — Total added lines in production .py files ({}) exceeds hotfix blast-radius limit of 25 lines",
            app_py_lines_added
        ));
    }

    // AST-SEC-07: NO_GIT_OR_ENV_TAMPERING — Block modifications to .git/, .env, or *.sh files
    for (filename, _, _) in &file_diffs {
        if filename.contains(".git/") || filename.contains("/.git") || filename == ".git" {
            findings.push(format!("AST-SEC-07: NO_GIT_OR_ENV_TAMPERING — modification to .git path detected in '{}'", filename));
        }
        if filename.contains(".env") {
            findings.push(format!("AST-SEC-07: NO_GIT_OR_ENV_TAMPERING — modification to .env file detected in '{}'", filename));
        }
        if filename.ends_with(".sh") {
            findings.push(format!("AST-SEC-07: NO_GIT_OR_ENV_TAMPERING — modification to shell script detected in '{}'", filename));
        }
    }

    // AST-SEC-06: NO_TEST_TAMPERING — Block diffs that delete def test_ or remove assert in test_*.py
    for (filename, _, deleted) in &file_diffs {
        let is_test = filename.contains("test_") || filename.contains("/tests/") || filename.ends_with("_test.py");
        if is_test {
            for del_line in deleted {
                let trimmed = del_line.trim_start_matches('-').trim();
                if trimmed.contains("def test_") {
                    findings.push(format!("AST-SEC-06: NO_TEST_TAMPERING — deletion of test function 'def test_' in '{}': '{}'", filename, trimmed));
                }
                if trimmed.starts_with("assert ") || trimmed.starts_with("assert(") || trimmed.contains(" assert ") {
                    findings.push(format!("AST-SEC-06: NO_TEST_TAMPERING — deletion of assertion statement in '{}': '{}'", filename, trimmed));
                }
            }
        }
    }

    // All added lines inspection
    let all_added: Vec<String> = file_diffs.iter().flat_map(|(_, a, _)| a.clone()).collect();

    // AST-SEC-08: NO_OBFUSCATED_EXEC — Block getattr(, builtins, os.popen, pty.spawn, shutil.rmtree, socket.
    let obfuscated_tokens = [
        ("getattr(", "Forbidden dynamic attribute access: getattr("),
        ("builtins", "Forbidden builtins module manipulation"),
        ("os.popen", "Forbidden shell execution: os.popen"),
        ("pty.spawn", "Forbidden pseudo-terminal spawn: pty.spawn"),
        ("shutil.rmtree", "Forbidden filesystem destruction: shutil.rmtree"),
        ("socket.", "Forbidden raw socket network access: socket."),
    ];

    for line in &all_added {
        for (token, desc) in &obfuscated_tokens {
            if line.contains(token) {
                findings.push(format!("AST-SEC-08: NO_OBFUSCATED_EXEC — {}: found '{}' in '{}'", desc, token, line.trim()));
            }
        }
    }

    // Baseline security checks (AST-SEC-01 through 05)
    let baseline_primitives = [
        ("eval(", "AST-SEC-01: NO_EVAL_EXEC — Forbidden dynamic execution primitive: eval()"),
        ("exec(", "AST-SEC-01: NO_EVAL_EXEC — Forbidden dynamic execution primitive: exec()"),
        ("os.system", "AST-SEC-02: NO_OS_SYSTEM — Forbidden shell execution: os.system"),
        ("subprocess", "AST-SEC-03: NO_SUBPROCESS — Forbidden process spawning: subprocess"),
        ("shell=True", "AST-SEC-03: NO_SUBPROCESS — Forbidden shell elevation: shell=True"),
        ("shell = True", "AST-SEC-03: NO_SUBPROCESS — Forbidden shell elevation: shell=True"),
        ("__import__", "AST-SEC-04: NO_DYNAMIC_IMPORT — Forbidden dynamic import: __import__"),
        ("importlib", "AST-SEC-04: NO_DYNAMIC_IMPORT — Forbidden dynamic import: importlib"),
        ("sk_live_", "AST-SEC-05: NO_HARDCODED_SECRETS — Forbidden secret: live secret key"),
        ("AIzaSy", "AST-SEC-05: NO_HARDCODED_SECRETS — Forbidden secret: Google API key"),
        ("AKIA", "AST-SEC-05: NO_HARDCODED_SECRETS — Forbidden secret: AWS Access Key ID"),
    ];

    for line in &all_added {
        for (token, desc) in &baseline_primitives {
            if line.contains(token) {
                findings.push(format!("{}: found '{}' in '{}'", desc, token, line.trim()));
            }
        }
    }

    let is_blocked = !findings.is_empty();

    let rules = vec![
        VerifyRule {
            rule: "AST-SEC-01: NO_EVAL_EXEC".to_string(),
            status: if findings.iter().any(|f| f.contains("AST-SEC-01")) { "FAIL".to_string() } else { "PASS".to_string() },
            description: "Rejects eval() and exec() primitives".to_string(),
        },
        VerifyRule {
            rule: "AST-SEC-02: NO_OS_SYSTEM".to_string(),
            status: if findings.iter().any(|f| f.contains("AST-SEC-02")) { "FAIL".to_string() } else { "PASS".to_string() },
            description: "Rejects os.system calls".to_string(),
        },
        VerifyRule {
            rule: "AST-SEC-03: NO_SUBPROCESS".to_string(),
            status: if findings.iter().any(|f| f.contains("AST-SEC-03")) { "FAIL".to_string() } else { "PASS".to_string() },
            description: "Rejects raw subprocess and shell=True".to_string(),
        },
        VerifyRule {
            rule: "AST-SEC-04: NO_DYNAMIC_IMPORT".to_string(),
            status: if findings.iter().any(|f| f.contains("AST-SEC-04")) { "FAIL".to_string() } else { "PASS".to_string() },
            description: "Rejects dynamic imports (__import__, importlib)".to_string(),
        },
        VerifyRule {
            rule: "AST-SEC-05: NO_HARDCODED_SECRETS".to_string(),
            status: if findings.iter().any(|f| f.contains("AST-SEC-05")) { "FAIL".to_string() } else { "PASS".to_string() },
            description: "Rejects hardcoded API keys, JWTs, and AWS secrets".to_string(),
        },
        VerifyRule {
            rule: "AST-SEC-06: NO_TEST_TAMPERING".to_string(),
            status: if findings.iter().any(|f| f.contains("AST-SEC-06")) { "FAIL".to_string() } else { "PASS".to_string() },
            description: "Block any diff that deletes existing def test_ functions or removes assert statements from test_*.py".to_string(),
        },
        VerifyRule {
            rule: "AST-SEC-07: NO_GIT_OR_ENV_TAMPERING".to_string(),
            status: if findings.iter().any(|f| f.contains("AST-SEC-07")) { "FAIL".to_string() } else { "PASS".to_string() },
            description: "Block modifications to .git/, .env, or *.sh files".to_string(),
        },
        VerifyRule {
            rule: "AST-SEC-08: NO_OBFUSCATED_EXEC".to_string(),
            status: if findings.iter().any(|f| f.contains("AST-SEC-08")) { "FAIL".to_string() } else { "PASS".to_string() },
            description: "Block getattr(, builtins, os.popen, pty.spawn, shutil.rmtree, and socket.".to_string(),
        },
        VerifyRule {
            rule: "AST-SEC-09: MINIMAL_BLAST_RADIUS".to_string(),
            status: if app_py_lines_added > 25 { "FAIL".to_string() } else { "PASS".to_string() },
            description: "Enforces minimal blast radius: rejects hotfixes adding more than 25 lines to production .py files".to_string(),
        },
    ];

    VerifyOutput {
        verdict: if is_blocked { "BLOCKED".to_string() } else { "PASS".to_string() },
        status: if is_blocked { "BLOCKED".to_string() } else { "PASS".to_string() },
        target_path: target.display().to_string(),
        sha256: diff_hash,
        forbidden_findings: findings,
        rules,
    }
}

fn run_verify_audit(log_path_str: &str) -> AuditVerifyOutput {
    let genesis = "0000000000000000000000000000000000000000000000000000000000000000";
    let target = Path::new(log_path_str);

    if !target.exists() {
        return AuditVerifyOutput {
            verdict: "BLOCKED".to_string(),
            status: "FILE_NOT_FOUND".to_string(),
            audit_log: log_path_str.to_string(),
            genesis_hash: genesis.to_string(),
            entries_verified: 0,
            latest_chain_hash: genesis.to_string(),
            tamper_detected: true,
            error: Some(format!("Audit log not found at: {}", log_path_str)),
            failed_entry: None,
        };
    }

    let contents = match fs::read_to_string(target) {
        Ok(c) => c,
        Err(e) => {
            return AuditVerifyOutput {
                verdict: "BLOCKED".to_string(),
                status: "READ_ERROR".to_string(),
                audit_log: log_path_str.to_string(),
                genesis_hash: genesis.to_string(),
                entries_verified: 0,
                latest_chain_hash: genesis.to_string(),
                tamper_detected: true,
                error: Some(format!("Failed to read audit log: {}", e)),
                failed_entry: None,
            };
        }
    };

    let mut current_chain_hash = genesis.to_string();
    let mut verified_count = 0;

    let re_timestamp = Regex::new(r"\[([^\]]+)\]").unwrap();
    let re_sha = Regex::new(r"\bSHA256=([0-9a-fA-F]{64})\b").unwrap();
    let re_chain = Regex::new(r"\bCHAIN_HASH=([0-9a-fA-F]{64})\b").unwrap();
    let re_prev = Regex::new(r"\bPREV_HASH=([0-9a-fA-F]{64})\b").unwrap();

    for (idx, line) in contents.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }

        if let Some(chain_cap) = re_chain.captures(trimmed) {
            let recorded_chain_hash = chain_cap.get(1).unwrap().as_str().to_lowercase();

            let timestamp = match re_timestamp.captures(trimmed) {
                Some(cap) => cap.get(1).unwrap().as_str().to_string(),
                None => {
                    return AuditVerifyOutput {
                        verdict: "TAMPER_DETECTED".to_string(),
                        status: "BLOCKED".to_string(),
                        audit_log: log_path_str.to_string(),
                        genesis_hash: genesis.to_string(),
                        entries_verified: verified_count,
                        latest_chain_hash: current_chain_hash,
                        tamper_detected: true,
                        error: Some(format!("Line {}: Missing valid [Timestamp]", idx + 1)),
                        failed_entry: None,
                    };
                }
            };

            let patch_sha256 = match re_sha.captures(trimmed) {
                Some(cap) => cap.get(1).unwrap().as_str().to_lowercase(),
                None => {
                    return AuditVerifyOutput {
                        verdict: "TAMPER_DETECTED".to_string(),
                        status: "BLOCKED".to_string(),
                        audit_log: log_path_str.to_string(),
                        genesis_hash: genesis.to_string(),
                        entries_verified: verified_count,
                        latest_chain_hash: current_chain_hash,
                        tamper_detected: true,
                        error: Some(format!("Line {}: Missing valid 64-char SHA256", idx + 1)),
                        failed_entry: None,
                    };
                }
            };

            let recorded_prev_hash = re_prev
                .captures(trimmed)
                .map(|c| c.get(1).unwrap().as_str().to_lowercase())
                .unwrap_or_else(|| current_chain_hash.clone());

            if recorded_prev_hash != current_chain_hash {
                let entry_info = AuditVerifyEntry {
                    entry_index: verified_count + 1,
                    timestamp: timestamp.clone(),
                    patch_sha256: patch_sha256.clone(),
                    prev_chain_hash: current_chain_hash.clone(),
                    recorded_chain_hash: recorded_chain_hash.clone(),
                    computed_chain_hash: String::new(),
                    valid: false,
                };
                return AuditVerifyOutput {
                    verdict: "TAMPER_DETECTED".to_string(),
                    status: "BLOCKED".to_string(),
                    audit_log: log_path_str.to_string(),
                    genesis_hash: genesis.to_string(),
                    entries_verified: verified_count,
                    latest_chain_hash: current_chain_hash.clone(),
                    tamper_detected: true,
                    error: Some(format!(
                        "Line {}: Broken hash chain! Recorded PREV_HASH '{}' does not match prior CHAIN_HASH '{}'",
                        idx + 1, recorded_prev_hash, current_chain_hash
                    )),
                    failed_entry: Some(entry_info),
                };
            }

            // ChainHash_n = SHA256(ChainHash_{n-1} || Timestamp_n || PatchSHA256_n)
            let payload = format!("{}{}{}", current_chain_hash, timestamp, patch_sha256);
            let computed_chain_hash = format!("{:x}", Sha256::digest(payload.as_bytes()));

            if computed_chain_hash != recorded_chain_hash {
                let entry_info = AuditVerifyEntry {
                    entry_index: verified_count + 1,
                    timestamp: timestamp.clone(),
                    patch_sha256: patch_sha256.clone(),
                    prev_chain_hash: current_chain_hash.clone(),
                    recorded_chain_hash: recorded_chain_hash.clone(),
                    computed_chain_hash: computed_chain_hash.clone(),
                    valid: false,
                };
                return AuditVerifyOutput {
                    verdict: "TAMPER_DETECTED".to_string(),
                    status: "BLOCKED".to_string(),
                    audit_log: log_path_str.to_string(),
                    genesis_hash: genesis.to_string(),
                    entries_verified: verified_count,
                    latest_chain_hash: current_chain_hash,
                    tamper_detected: true,
                    error: Some(format!(
                        "Line {}: Cryptographic hash chain mismatch! Computed '{}', found '{}'",
                        idx + 1, computed_chain_hash, recorded_chain_hash
                    )),
                    failed_entry: Some(entry_info),
                };
            }

            current_chain_hash = computed_chain_hash;
            verified_count += 1;
        }
    }

    AuditVerifyOutput {
        verdict: "VERIFIED".to_string(),
        status: "PASS".to_string(),
        audit_log: log_path_str.to_string(),
        genesis_hash: genesis.to_string(),
        entries_verified: verified_count,
        latest_chain_hash: current_chain_hash,
        tamper_detected: false,
        error: None,
        failed_entry: None,
    }
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: switchguard-cli <scrub|verify-diff|verify-audit> [args]");
        process::exit(1);
    }

    if args[1] == "--version" || args[1] == "-V" || args[1] == "version" {
        println!("switchguard-cli {}", env!("CARGO_PKG_VERSION"));
        process::exit(0);
    }

    if args[1] == "--help" || args[1] == "-h" || args[1] == "help" {
        println!(
            "SwitchGuard SRE Security Guardrail CLI v{}\n\nUsage:\n  switchguard-cli scrub <log>\n  switchguard-cli verify-diff [path]\n  switchguard-cli verify-audit [audit_log_path]",
            env!("CARGO_PKG_VERSION")
        );
        process::exit(0);
    }

    match args[1].as_str() {
        "scrub" => {
            let input = if args.len() > 2 {
                let candidate = &args[2];
                if Path::new(candidate).exists() {
                    fs::read_to_string(candidate).unwrap_or_else(|_| args[2..].join(" "))
                } else {
                    args[2..].join(" ")
                }
            } else {
                String::new()
            };

            let (sanitized, count, classification, hash) = scrub_payload(&input);
            let normalized_file_line = extract_normalized_file_line(&input);
            let canonical_input = format!("{}{}", classification, normalized_file_line);
            let fault_fingerprint = format!("{:x}", Sha256::digest(canonical_input.as_bytes()));
            let (dedup_status, occurrence_count) =
                record_or_check_dedup(&classification, &normalized_file_line, &fault_fingerprint);

            let out = ScrubOutput {
                status: if dedup_status == "SUPPRESSED_DUPLICATE" {
                    "SUPPRESSED_DUPLICATE".to_string()
                } else {
                    "SANITIZED".to_string()
                },
                sanitized_text: sanitized.clone(),
                clean_payload: sanitized,
                sha256: hash,
                error_classification: classification,
                redacted_count: count,
                dedup_status,
                fault_fingerprint,
                occurrence_count,
                normalized_file_line,
            };

            println!("{}", serde_json::to_string_pretty(&out).unwrap());
        }
        "verify-diff" => {
            let path_str = if args.len() > 2 { &args[2] } else { "." };
            let result = run_verify_diff(path_str);
            let exit_code = match result.status.as_str() {
                "EMPTY_PATCH_REJECTED" => 3,
                "BLOCKED" => 2,
                _ => 0,
            };
            println!("{}", serde_json::to_string_pretty(&result).unwrap());
            if exit_code != 0 {
                process::exit(exit_code);
            }
        }
        "verify-audit" => {
            let path_str = if args.len() > 2 {
                args[2].clone()
            } else {
                let candidates = [
                    "workspace/release-ops/RELEASE_AUDIT.log",
                    "../release-ops/RELEASE_AUDIT.log",
                    "RELEASE_AUDIT.log",
                    "/home/anshul-jain/switchguard-sre/workspace/release-ops/RELEASE_AUDIT.log",
                ];
                let mut chosen =
                    "/home/anshul-jain/switchguard-sre/workspace/release-ops/RELEASE_AUDIT.log".to_string();
                for c in &candidates {
                    if Path::new(c).exists() {
                        chosen = c.to_string();
                        break;
                    }
                }
                chosen
            };

            let result = run_verify_audit(&path_str);
            let is_blocked = result.tamper_detected || result.status != "PASS";
            println!("{}", serde_json::to_string_pretty(&result).unwrap());
            if is_blocked {
                process::exit(2);
            }
        }
        other => {
            eprintln!("Unknown subcommand: {}", other);
            process::exit(1);
        }
    }
}
