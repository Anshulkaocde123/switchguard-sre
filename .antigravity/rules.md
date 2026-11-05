# SwitchGuard Antigravity Rules

## 1. Directory Isolation
- Agents must operate strictly within their assigned working directory:
  - `sre-sentinel` -> `/workspace/telemetry`
  - `sre-repro` -> `/workspace/sandbox-app`
  - `sre-clerk` -> `/workspace/release-ops`

## 2. Security Verification
- Automatically run `switchguard-cli verify-diff workspace/sandbox-app` on any changes to `cart_service.py`.
- Never commit hardcoded API keys, JWTs, or secrets.

## 3. Communication Limits (Issue #1226 & #1097)
- Terminal tracebacks posted to rooms must be <= 30 lines and < 1,500 characters.
- Render all scorecards, diffs, and test results as direct Markdown in chat.
