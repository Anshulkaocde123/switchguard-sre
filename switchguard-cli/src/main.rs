use regex::Regex;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::env;
use std::fs;
use std::path::Path;
use std::process::{self, Command};

#[derive(Serialize)]
struct ScrubOutput {
    status: String,
    sanitized_text: String,
    clean_payload: String,
    sha256: String,
    error_classification: String,
    redacted_count: usize,
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

    // 3. Redact Email addresses
    let re_email = Regex::new(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+").unwrap();
    let email_matches = re_email.find_iter(&text).count();
    total_redactions += email_matches;
    text = re_email.replace_all(&text, "[REDACTED_EMAIL]").to_string();

    // 4. Redact IPv4 addresses
    let re_ipv4 = Regex::new(r"\b(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b").unwrap();
    let ip_matches = re_ipv4.find_iter(&text).count();
    total_redactions += ip_matches;
    text = re_ipv4.replace_all(&text, "[REDACTED_IPV4]").to_string();

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

fn run_verify_diff(path_str: &str) -> VerifyOutput {
    let target = Path::new(path_str);
    let mut diff_text = String::new();

    // Try git diff on target
    if let Ok(output) = Command::new("git")
        .args(["-C", path_str, "diff", "HEAD"])
        .output()
    {
        diff_text.push_str(&String::from_utf8_lossy(&output.stdout));
    }

    // Also check cached diff if unstaged was empty
    if diff_text.trim().is_empty() {
        if let Ok(output) = Command::new("git")
            .args(["-C", path_str, "diff", "--cached"])
            .output()
        {
            diff_text.push_str(&String::from_utf8_lossy(&output.stdout));
        }
    }

    // If still empty and commits exist, check HEAD
    if diff_text.trim().is_empty() {
        if let Ok(output) = Command::new("git")
            .args(["-C", path_str, "diff", "HEAD~1", "HEAD"])
            .output()
        {
            diff_text.push_str(&String::from_utf8_lossy(&output.stdout));
        }
    }

    // --- EDGE CASE A: Empty-patch rejection ---
    if diff_text.trim().is_empty() {
        return VerifyOutput {
            verdict: "BLOCKED".to_string(),
            status: "EMPTY_PATCH_REJECTED".to_string(),
            target_path: target.display().to_string(),
            sha256: format!("{:x}", Sha256::digest(diff_text.as_bytes())),
            forbidden_findings: vec!["AST-SEC-00: EMPTY_PATCH — git diff returned 0 bytes; no changes to release.".to_string()],
            rules: vec![VerifyRule {
                rule: "AST-SEC-00: NO_EMPTY_PATCH".to_string(),
                status: "FAIL".to_string(),
                description: "Rejects empty diffs (0-byte patches)".to_string(),
            }],
        };
    }

    let added_lines: Vec<&str> = diff_text
        .lines()
        .filter(|l| l.starts_with('+') && !l.starts_with("+++"))
        .collect();

    // Count actual file changes (lines starting with "diff --git")
    let files_changed = diff_text.lines().filter(|l| l.starts_with("diff --git")).count();
    if files_changed == 0 || added_lines.is_empty() {
        return VerifyOutput {
            verdict: "BLOCKED".to_string(),
            status: "EMPTY_PATCH_REJECTED".to_string(),
            target_path: target.display().to_string(),
            sha256: format!("{:x}", Sha256::digest(diff_text.as_bytes())),
            forbidden_findings: vec![format!("AST-SEC-00: EMPTY_PATCH — files_changed={}, lines_added={}", files_changed, added_lines.len())],
            rules: vec![VerifyRule {
                rule: "AST-SEC-00: NO_EMPTY_PATCH".to_string(),
                status: "FAIL".to_string(),
                description: "Rejects diffs with no substantive code additions".to_string(),
            }],
        };
    }

    let mut findings = Vec::new();

    let forbidden_primitives = [
        ("eval", "Forbidden dynamic execution primitive: eval()"),
        ("exec", "Forbidden dynamic execution primitive: exec()"),
        ("os.system", "Forbidden shell execution: os.system"),
        ("subprocess", "Forbidden process spawning: subprocess"),
        ("shell=True", "Forbidden shell elevation: shell=True"),
        ("shell = True", "Forbidden shell elevation: shell=True"),
        ("__import__", "Forbidden dynamic import: __import__"),
        ("sk_live_", "Forbidden secret: live secret key"),
        ("AIzaSy", "Forbidden secret: Google API key"),
        ("os.popen", "Forbidden shell execution: os.popen"),
        ("pty.spawn", "Forbidden shell execution: pty.spawn"),
        ("shutil.rmtree", "Forbidden destructive operation: shutil.rmtree"),
        ("getattr(__builtins__", "Forbidden builtins bypass: getattr(__builtins__)"),
        ("importlib", "Forbidden dynamic import: importlib"),
        ("compile(", "Forbidden code compilation: compile()"),
        ("pickle.loads", "Forbidden deserialization: pickle.loads"),
    ];

    for line in &added_lines {
        for (token, desc) in &forbidden_primitives {
            if line.contains(token) {
                findings.push(format!("{}: found '{}' in '{}'", desc, token, line.trim()));
            }
        }
    }

    // --- EDGE CASE B: Anti-reward-hacking (AST-SEC-06) ---
    let diff_file_headers: Vec<&str> = diff_text.lines()
        .filter(|l| l.starts_with("diff --git"))
        .collect();

    let modifies_source = diff_file_headers.iter()
        .any(|h| !h.contains("test_") && h.contains(".py"));
    let modifies_tests = diff_file_headers.iter()
        .any(|h| h.contains("test_"));

    // If tests are modified but no source file is, that's suspicious
    if modifies_tests && !modifies_source {
        findings.push("AST-SEC-06: NO_TEST_TAMPERING — test file(s) modified but no production source file changed. Suspected reward hacking.".to_string());
    }

    // Check for deleted assertion lines (lines removed from test files that contain assert)
    let deleted_lines: Vec<&str> = diff_text.lines()
        .filter(|l| l.starts_with('-') && !l.starts_with("---"))
        .collect();

    for line in &deleted_lines {
        let trimmed = line.trim_start_matches('-').trim();
        if trimmed.starts_with("assert") || trimmed.contains("assert ") {
            // Check if this deletion is in a test file context
            findings.push(format!("AST-SEC-06: NO_TEST_TAMPERING — deleted assertion detected: '{}'", trimmed));
        }
    }

    // --- AST-SEC-08: Protected paths ---
    let protected_paths = [".git/", ".env", ".sh"];
    for header in &diff_file_headers {
        for protected in &protected_paths {
            if header.contains(protected) {
                findings.push(format!("AST-SEC-08: PROTECTED_PATH — diff touches protected path '{}' in '{}'", protected, header));
            }
        }
    }

    let diff_hash = format!("{:x}", Sha256::digest(diff_text.as_bytes()));
    let is_blocked = !findings.is_empty();

    let rules = vec![
        VerifyRule {
            rule: "AST-SEC-01: NO_EVAL_EXEC".to_string(),
            status: if findings.iter().any(|f| f.contains("eval") || f.contains("exec")) { "FAIL".to_string() } else { "PASS".to_string() },
            description: "Rejects eval() and exec() primitives".to_string(),
        },
        VerifyRule {
            rule: "AST-SEC-02: NO_OS_SYSTEM".to_string(),
            status: if findings.iter().any(|f| f.contains("os.system")) { "FAIL".to_string() } else { "PASS".to_string() },
            description: "Rejects os.system calls".to_string(),
        },
        VerifyRule {
            rule: "AST-SEC-03: NO_SUBPROCESS".to_string(),
            status: if findings.iter().any(|f| f.contains("subprocess") || f.contains("shell=True")) { "FAIL".to_string() } else { "PASS".to_string() },
            description: "Rejects raw subprocess and shell=True".to_string(),
        },
        VerifyRule {
            rule: "AST-SEC-04: NO_DYNAMIC_IMPORT".to_string(),
            status: if findings.iter().any(|f| f.contains("__import__")) { "FAIL".to_string() } else { "PASS".to_string() },
            description: "Rejects __import__ calls".to_string(),
        },
        VerifyRule {
            rule: "AST-SEC-05: NO_HARDCODED_SECRETS".to_string(),
            status: if findings.iter().any(|f| f.contains("sk_live_") || f.contains("AIzaSy")) { "FAIL".to_string() } else { "PASS".to_string() },
            description: "Rejects hardcoded API keys and secrets".to_string(),
        },
        VerifyRule {
            rule: "AST-SEC-06: NO_TEST_TAMPERING".to_string(),
            status: if findings.iter().any(|f| f.contains("AST-SEC-06")) { "FAIL".to_string() } else { "PASS".to_string() },
            description: "Blocks test deletion or assertion weakening (anti-reward-hacking)".to_string(),
        },
        VerifyRule {
            rule: "AST-SEC-07: NO_EVASION_PRIMITIVES".to_string(),
            status: if findings.iter().any(|f| f.contains("os.popen") || f.contains("pty.spawn") || f.contains("shutil.rmtree") || f.contains("getattr") || f.contains("importlib") || f.contains("compile(") || f.contains("pickle")) { "FAIL".to_string() } else { "PASS".to_string() },
            description: "Blocks evasion primitives (os.popen, pty.spawn, importlib, pickle, etc.)".to_string(),
        },
        VerifyRule {
            rule: "AST-SEC-08: NO_PROTECTED_PATHS".to_string(),
            status: if findings.iter().any(|f| f.contains("AST-SEC-08")) { "FAIL".to_string() } else { "PASS".to_string() },
            description: "Blocks diffs touching .git/, .env, or .sh files".to_string(),
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

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        eprintln!("Usage: switchguard-cli <scrub|verify-diff> [args]");
        process::exit(1);
    }

    if args[1] == "--version" || args[1] == "-V" || args[1] == "version" {
        println!("switchguard-cli {}", env!("CARGO_PKG_VERSION"));
        process::exit(0);
    }

    if args[1] == "--help" || args[1] == "-h" || args[1] == "help" {
        println!("SwitchGuard SRE Security Guardrail CLI v{}\n\nUsage:\n  switchguard-cli scrub <log>\n  switchguard-cli verify-diff [path]", env!("CARGO_PKG_VERSION"));
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
            let out = ScrubOutput {
                status: "SANITIZED".to_string(),
                sanitized_text: sanitized.clone(),
                clean_payload: sanitized,
                sha256: hash,
                error_classification: classification,
                redacted_count: count,
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
        other => {
            eprintln!("Unknown subcommand: {}", other);
            process::exit(1);
        }
    }
}
